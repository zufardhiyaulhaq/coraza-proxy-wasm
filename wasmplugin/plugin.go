// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

func NewVMContext() types.VMContext {
	return &vmContext{}
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &corazaPlugin{}
}

type wafMap struct {
	kv         map[string]coraza.WAF
	defaultKey string
}

func newWAFMap(capacity int) wafMap {
	return wafMap{
		kv: make(map[string]coraza.WAF, capacity),
	}
}

func (m *wafMap) put(key string, waf coraza.WAF) error {
	if len(key) == 0 {
		return errors.New("empty WAF key")
	}

	m.kv[key] = waf
	return nil
}

func (m *wafMap) setDefaultKey(key string) error {
	if len(key) == 0 {
		return errors.New("empty default WAF key")
	}

	if _, ok := m.kv[key]; ok {
		m.defaultKey = key
		return nil
	}

	return fmt.Errorf("unknown default WAF key %q", key)
}

func (m *wafMap) getWAFOrDefault(key string) (coraza.WAF, bool, error) {
	if w, ok := m.kv[key]; ok {
		return w, false, nil
	}

	if len(m.defaultKey) == 0 {
		return nil, false, errors.New("no default WAF key")
	}

	return m.kv[m.defaultKey], true, nil
}

type corazaPlugin struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext
	perAuthorityWAFs wafMap
	metricLabelsKV   []string
	metrics          *wafMetrics
}

func (ctx *corazaPlugin) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil && err != types.ErrorStatusNotFound {
		proxywasm.LogCriticalf("Failed to read plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	config, err := parsePluginConfiguration(data, proxywasm.LogInfo)
	if err != nil {
		proxywasm.LogCriticalf("Failed to parse plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	perAuthorityWAFs := newWAFMap(len(config.directivesMap))
	for name, directives := range config.directivesMap {
		// First we initialize our waf and our seclang parser
		conf := coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDebugLogger(debuglog.DefaultWithPrinterFactory(logPrinterFactory)).
			// TODO(anuraaga): Make this configurable in plugin configuration.
			// WithRequestBodyLimit(1024 * 1024 * 1024).
			// WithRequestBodyInMemoryLimit(1024 * 1024 * 1024).
			// Limit equal to MemoryLimit: TinyGo compilation will prevent
			// buffering request body to files anyways.
			WithRootFS(root)

		waf, err := coraza.NewWAF(conf.WithDirectives(strings.Join(directives, "\n")))
		if err != nil {
			proxywasm.LogCriticalf("Failed to parse directives: %v", err)
			return types.OnPluginStartStatusFailed
		}

		err = perAuthorityWAFs.put(name, waf)
		if err != nil {
			proxywasm.LogCriticalf("Failed to register authority WAF: %v", err)
			return types.OnPluginStartStatusFailed
		}
	}

	if len(config.defaultDirectives) > 0 {
		if err := perAuthorityWAFs.setDefaultKey(config.defaultDirectives); err != nil {
			proxywasm.LogCriticalf("Failed to set the default directives: %v", err)
			return types.OnPluginStartStatusFailed
		}
	}

	ctx.perAuthorityWAFs = perAuthorityWAFs
	for k, v := range config.metricLabels {
		ctx.metricLabelsKV = append(ctx.metricLabelsKV, k, v)
	}
	ctx.metrics = NewWAFMetrics()

	return types.OnPluginStartStatusOK
}

func (ctx *corazaPlugin) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID:        contextID,
		metrics:          ctx.metrics,
		metricLabelsKV:   ctx.metricLabelsKV,
		perAuthorityWAFs: ctx.perAuthorityWAFs,
	}
}

type interruptionPhase int8

func (p interruptionPhase) isInterrupted() bool {
	return p != interruptionPhaseNone
}

func (p interruptionPhase) String() string {
	switch p {
	case interruptionPhaseHttpRequestHeaders:
		return "http_request_headers"
	case interruptionPhaseHttpRequestBody:
		return "http_request_body"
	case interruptionPhaseHttpResponseHeaders:
		return "http_response_headers"
	case interruptionPhaseHttpResponseBody:
		return "http_response_body"
	default:
		return "no interruption yet"
	}
}

const (
	interruptionPhaseNone                = iota
	interruptionPhaseHttpRequestHeaders  = iota
	interruptionPhaseHttpRequestBody     = iota
	interruptionPhaseHttpResponseHeaders = iota
	interruptionPhaseHttpResponseBody    = iota
)

type httpContext struct {
	// Embed the default http context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultHttpContext
	contextID             uint32
	perAuthorityWAFs      wafMap
	tx                    ctypes.Transaction
	httpProtocol          string
	processedRequestBody  bool
	processedResponseBody bool
	bodyReadIndex         int
	metrics               *wafMetrics
	interruptedAt         interruptionPhase
	logger                debuglog.Logger
	metricLabelsKV        []string
}

func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	defer logTime("OnHttpRequestHeaders", currentTime())

	ctx.metrics.CountTX()

	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err == nil {
		if waf, isDefault, resolveWAFErr := ctx.perAuthorityWAFs.getWAFOrDefault(authority); resolveWAFErr == nil {
			ctx.tx = waf.NewTransaction()

			logFields := []debuglog.ContextField{debuglog.Uint("context_id", uint(ctx.contextID))}
			if !isDefault {
				logFields = append(logFields, debuglog.Str("authority", authority))
			}
			ctx.logger = ctx.tx.DebugLogger().With(logFields...)

			// CRS rules tend to expect Host even with HTTP/2
			ctx.tx.AddRequestHeader("Host", authority)
			ctx.tx.SetServerName(parseServerName(ctx.logger, authority))

			if !isDefault {
				ctx.metricLabelsKV = append(ctx.metricLabelsKV, "authority", authority)
			}
		} else {
			proxywasm.LogWarnf("Failed to resolve WAF for authority %q: %v", authority, resolveWAFErr)
			return types.ActionContinue
		}
	} else {
		proxywasm.LogWarnf("Failed to get the :authority pseudo-header: %v", err)
		return types.ActionContinue
	}

	tx := ctx.tx

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.
	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// OnHttpRequestHeaders does not terminate if IP/Port retrieve goes wrong
	srcIP, srcPort := retrieveAddressInfo(ctx.logger, "source")
	dstIP, dstPort := retrieveAddressInfo(ctx.logger, "destination")

	tx.ProcessConnection(srcIP, srcPort, dstIP, dstPort)

	// Note the pseudo-header :path includes the query.
	// See https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1
	uri, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		ctx.logger.Error().
			Err(err).
			Msg("Failed to get :path")
		return types.ActionContinue
	}

	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		ctx.logger.Error().
			Err(err).
			Msg("Failed to get :method")
		return types.ActionContinue
	}

	protocol, err := proxywasm.GetProperty([]string{"request", "protocol"})
	if err != nil {
		// TODO(anuraaga): HTTP protocol is commonly required in WAF rules, we should probably
		// fail fast here, but proxytest does not support properties yet.
		protocol = []byte("HTTP/2.0")
	}

	ctx.httpProtocol = string(protocol)

	tx.ProcessURI(uri, method, ctx.httpProtocol)

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		ctx.logger.Error().Err(err).Msg("Failed to get request headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		return ctx.handleInterruption(interruptionPhaseHttpRequestHeaders, interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	defer logTime("OnHttpRequestBody", currentTime())

	if ctx.interruptedAt.isInterrupted() {
		ctx.logger.Error().
			Str("interruption_handled_phase", ctx.interruptedAt.String()).
			Msg("Interruption already handled")
		return types.ActionPause
	}

	if ctx.processedRequestBody {
		return types.ActionContinue
	}

	if ctx.tx == nil {
		return types.ActionContinue
	}

	tx := ctx.tx

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to request body data if SecRequestBodyAccess is set to false
	if !tx.IsRequestBodyAccessible() {
		ctx.logger.Debug().Msg("Skipping request body inspection, SecRequestBodyAccess is off.")
		// ProcessRequestBody is still performed for phase 2 rules, checking already populated variables
		ctx.processedRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			ctx.logger.Error().Err(err).Msg("Failed to process request body")
			return types.ActionContinue
		}

		if interruption != nil {
			return ctx.handleInterruption(interruptionPhaseHttpRequestBody, interruption)
		}

		return types.ActionContinue
	}

	if bodySize > 0 {
		b, err := proxywasm.GetHttpRequestBody(ctx.bodyReadIndex, bodySize)
		if err == nil {
			interruption, _, err := tx.WriteRequestBody(b)
			if err != nil {
				ctx.logger.Error().Err(err).Msg("Failed to write request body")
				return types.ActionContinue
			}

			if interruption != nil {
				return ctx.handleInterruption(interruptionPhaseHttpRequestBody, interruption)
			}

			ctx.bodyReadIndex += bodySize
		} else if err != types.ErrorStatusNotFound {
			// When using FWT sometimes (it is inconsistent) we receive calls where ctx.bodyReadIndex == bodySize
			// meaning that the incoming size in the body is the same as the already read body.
			// When that happens, this code fails to retrieve the body through proxywasm.GetHttpRequestBody
			// as the total body is from 0 up to X bytes and since the last bodySize = X it attempts to read
			// from X up to X bytes and it returns a types.ErrorStatusNotFound. This could happen despite
			// endOfStream being true or false.
			// The tests in 920410 show this problem.
			// TODO(jcchavezs): Verify if this is a FTW problem.
			ctx.logger.Error().
				Err(err).
				Int("body_read_index", ctx.bodyReadIndex).
				Int("body_size", bodySize).
				Msg("Failed to read request body")
			return types.ActionContinue
		}
	}

	if endOfStream {
		ctx.processedRequestBody = true
		ctx.bodyReadIndex = 0 // cleaning for further usage
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			ctx.logger.Error().
				Err(err).
				Msg("Failed to process request body")
			return types.ActionContinue
		}
		if interruption != nil {
			return ctx.handleInterruption(interruptionPhaseHttpRequestBody, interruption)
		}

		return types.ActionContinue
	}

	return types.ActionPause
}

func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	defer logTime("OnHttpResponseHeaders", currentTime())

	if ctx.interruptedAt.isInterrupted() {
		// Handling the interruption (see handleInterruption) generates a HttpResponse with the required interruption status code.
		// If handleInterruption is raised during OnHttpRequestHeaders or OnHttpRequestBody, the crafted response is sent
		// downstream via the filter chain, therefore OnHttpResponseHeaders is called. It has to continue to properly send back the interruption action.
		// A doublecheck might be eventually added, checking that the :status header matches the expected interruption status code.
		// See https://github.com/corazawaf/coraza-proxy-wasm/pull/126
		ctx.logger.Debug().
			Str("interruption_handled_phase", ctx.interruptedAt.String()).
			Msg("Interruption already handled, sending downstream the local response")
		return types.ActionContinue
	}

	if ctx.tx == nil {
		return types.ActionContinue
	}

	tx := ctx.tx

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Requests without body won't call OnHttpRequestBody, but there are rules in the request body
	// phase that still need to be executed. If they haven't been executed yet, now is the time.
	if !ctx.processedRequestBody {
		ctx.processedRequestBody = true
		interruption, err := tx.ProcessRequestBody()
		if err != nil {
			ctx.logger.Error().
				Err(err).Msg("Failed to process request body")
			return types.ActionContinue
		}
		if interruption != nil {
			return ctx.handleInterruption(interruptionPhaseHttpResponseHeaders, interruption)
		}
	}

	status, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		ctx.logger.Error().
			Err(err).
			Msg("Failed to get :status")
		return types.ActionContinue
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		code = 0
	}

	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		ctx.logger.Error().
			Err(err).
			Msg("Failed to get response headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddResponseHeader(h[0], h[1])
	}

	interruption := tx.ProcessResponseHeaders(code, ctx.httpProtocol)
	if interruption != nil {
		return ctx.handleInterruption(interruptionPhaseHttpResponseHeaders, interruption)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpResponseBody(bodySize int, endOfStream bool) types.Action {
	defer logTime("OnHttpResponseBody", currentTime())

	if ctx.interruptedAt.isInterrupted() {
		// At response body phase, proxy-wasm currently relies on emptying the response body as a way of
		// interruption the response. See https://github.com/corazawaf/coraza-proxy-wasm/issues/26.
		// If OnHttpResponseBody is called again and an interruption has already been raised, it means that
		// we have to keep going with the sanitization of the response, emptying it.
		// Sending the crafted HttpResponse with empty body, we don't expect to trigger OnHttpResponseBody
		ctx.logger.Debug().
			Str("interruption_handled_phase", ctx.interruptedAt.String()).
			Msg("Response body interruption already handled, keeping replacing the body")
		// Interruption happened, we don't want to send response body data
		return replaceResponseBodyWhenInterrupted(ctx.logger, bodySize)
	}

	if ctx.tx == nil {
		return types.ActionContinue
	}

	tx := ctx.tx

	if tx.IsRuleEngineOff() {
		return types.ActionContinue
	}

	// Do not perform any action related to response body data if SecResponseBodyAccess is set to false
	if !tx.IsResponseBodyAccessible() {
		ctx.logger.Debug().Msg("Skipping response body inspection, SecResponseBodyAccess is off.")
		// ProcessResponseBody is performed for phase 4 rules, checking already populated variables
		if !ctx.processedResponseBody {
			interruption, err := tx.ProcessResponseBody()
			if err != nil {
				ctx.logger.Error().Err(err).Msg("Failed to process response body")
				return types.ActionContinue
			}
			ctx.processedResponseBody = true
			if interruption != nil {
				// Proxy-wasm can not anymore deny the response. The best interruption is emptying the body
				// Coraza Multiphase evaluation will help here avoiding late interruptions
				ctx.bodyReadIndex = bodySize // hacky: bodyReadIndex stores the body size that has to be replaced
				return ctx.handleInterruption(interruptionPhaseHttpResponseBody, interruption)
			}
		}
		return types.ActionContinue
	}

	if bodySize > 0 {
		body, err := proxywasm.GetHttpResponseBody(ctx.bodyReadIndex, bodySize)
		if err == nil {
			interruption, _, err := tx.WriteResponseBody(body)
			if err != nil {
				ctx.logger.Error().Err(err).Msg("Failed to write response body")
				return types.ActionContinue
			}
			// bodyReadIndex has to be updated before evaluating the interruption
			// it is internally needed to replace the full body if the tx is interrupted
			ctx.bodyReadIndex += bodySize
			if interruption != nil {
				return ctx.handleInterruption(interruptionPhaseHttpResponseBody, interruption)
			}
		} else if err != types.ErrorStatusNotFound {
			ctx.logger.Error().
				Int("body_read_index", ctx.bodyReadIndex).
				Int("body_size", bodySize).
				Err(err).
				Msg("Failed to read response body")
			return types.ActionContinue
		}
	}

	if endOfStream {
		// We have already sent response headers, an unauthorized response can not be sent anymore,
		// but we can still drop the response to prevent leaking sensitive content.
		// The error will also be logged by Coraza.
		ctx.processedResponseBody = true
		interruption, err := tx.ProcessResponseBody()
		if err != nil {
			ctx.logger.Error().
				Err(err).
				Msg("Failed to process response body")
			return types.ActionContinue
		}
		if interruption != nil {
			return ctx.handleInterruption(interruptionPhaseHttpResponseBody, interruption)
		}
		return types.ActionContinue
	}
	// Wait until we see the entire body. It has to be buffered in order to check that it is fully legit
	// before sending it downstream
	return types.ActionPause
}

func (ctx *httpContext) OnHttpStreamDone() {
	defer logTime("OnHttpStreamDone", currentTime())
	tx := ctx.tx

	if tx != nil {
		if !tx.IsRuleEngineOff() && !ctx.interruptedAt.isInterrupted() {
			// Responses without body won't call OnHttpResponseBody, but there are rules in the response body
			// phase that still need to be executed. If they haven't been executed yet, and there has not been a previous
			// interruption, now is the time.
			if !ctx.processedResponseBody {
				ctx.logger.Info().Msg("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes")
				ctx.processedResponseBody = true
				_, err := tx.ProcessResponseBody()
				if err != nil {
					ctx.logger.Error().
						Err(err).
						Msg("Failed to process response body")
				}
			}
		}

		// ProcessLogging is still called even if RuleEngine is off for potential logs generated before the engine is turned off.
		// Internally, if the engine is off, no log phase rules are evaluated
		ctx.tx.ProcessLogging()

		_ = ctx.tx.Close()
		ctx.logger.Info().Msg("Finished")
		logMemStats()
	}
}

const noGRPCStream int32 = -1
const defaultInterruptionStatusCode int = 403

func (ctx *httpContext) handleInterruption(phase interruptionPhase, interruption *ctypes.Interruption) types.Action {
	if ctx.interruptedAt.isInterrupted() {
		// handleInterruption should never be called more than once
		panic("Interruption already handled")
	}

	ctx.metrics.CountTXInterruption(phase.String(), interruption.RuleID, ctx.metricLabelsKV)

	ctx.logger.Info().
		Str("action", interruption.Action).
		Str("phase", phase.String()).
		Msg("Transaction interrupted")

	ctx.interruptedAt = phase
	if phase == interruptionPhaseHttpResponseBody {
		return replaceResponseBodyWhenInterrupted(ctx.logger, ctx.bodyReadIndex)
	}

	statusCode := interruption.Status
	if statusCode == 0 {
		statusCode = defaultInterruptionStatusCode
	}
	if err := proxywasm.SendHttpResponse(uint32(statusCode), nil, nil, noGRPCStream); err != nil {
		panic(err)
	}

	// SendHttpResponse must be followed by ActionPause in order to stop malicious content
	return types.ActionPause
}

func logError(error ctypes.MatchedRule) {
	msg := error.ErrorLog(0)
	switch error.Rule().Severity() {
	case ctypes.RuleSeverityEmergency:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityAlert:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityCritical:
		proxywasm.LogCritical(msg)
	case ctypes.RuleSeverityError:
		proxywasm.LogError(msg)
	case ctypes.RuleSeverityWarning:
		proxywasm.LogWarn(msg)
	case ctypes.RuleSeverityNotice:
		proxywasm.LogInfo(msg)
	case ctypes.RuleSeverityInfo:
		proxywasm.LogInfo(msg)
	case ctypes.RuleSeverityDebug:
		proxywasm.LogDebug(msg)
	}
}

// retrieveAddressInfo retrieves address properties from the proxy
// Expected targets are "source" or "destination"
// Envoy ref: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes#connection-attributes
func retrieveAddressInfo(logger debuglog.Logger, target string) (string, int) {
	var targetIP, targetPortStr string
	var targetPort int
	targetAddressRaw, err := proxywasm.GetProperty([]string{target, "address"})
	if err != nil {
		logger.Debug().
			Err(err).
			Msg(fmt.Sprintf("Failed to get %s address", target))
	} else {
		targetIP, targetPortStr, err = net.SplitHostPort(string(targetAddressRaw))
		if err != nil {
			logger.Debug().
				Err(err).
				Msg(fmt.Sprintf("Failed to parse %s address", target))
		}
	}
	targetPortRaw, err := proxywasm.GetProperty([]string{target, "port"})
	if err == nil {
		targetPort, err = parsePort(targetPortRaw)
		if err != nil {
			logger.Debug().
				Err(err).
				Msg(fmt.Sprintf("Failed to parse %s port", target))
		}
	} else if targetPortStr != "" {
		// If GetProperty fails we rely on the port inside the Address property
		// Mostly useful for proxies other than Envoy
		targetPort, err = strconv.Atoi(targetPortStr)
		if err != nil {
			logger.Debug().
				Err(err).
				Msg(fmt.Sprintf("Failed to get %s port", target))

		}
	}
	return targetIP, targetPort
}

// parsePort converts port, retrieved as little-endian bytes, into int
func parsePort(b []byte) (int, error) {
	// Port attribute ({"source", "port"}) is populated as uint64 (8 byte)
	// Ref: https://github.com/envoyproxy/envoy/blob/1b3da361279a54956f01abba830fc5d3a5421828/source/common/network/utility.cc#L201
	if len(b) < 8 {
		return 0, errors.New("port bytes not found")
	}
	// 0 < Port number <= 65535, therefore the retrieved value should never exceed 16 bits
	// and correctly fit int (at least 32 bits in size)
	unsignedInt := binary.LittleEndian.Uint64(b)
	if unsignedInt > math.MaxInt32 {
		return 0, errors.New("port conversion error")
	}
	return int(unsignedInt), nil
}

// replaceResponseBodyWhenInterrupted address an interruption raised during phase 4.
// At this phase, response headers are already sent downstream, therefore an interruption
// can not change anymore the status code, but only tweak the response body
func replaceResponseBodyWhenInterrupted(logger debuglog.Logger, bodySize int) types.Action {
	// TODO(M4tteoP): Update response body interruption logic after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
	// Currently returns a body filled with null bytes that replaces the sensitive data potentially leaked
	err := proxywasm.ReplaceHttpResponseBody(bytes.Repeat([]byte("\x00"), bodySize))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to replace response body")
		return types.ActionContinue
	}
	logger.Warn().Msg("Response body intervention occurred: body replaced")
	return types.ActionContinue
}

// parseServerName parses :authority pseudo-header in order to retrieve the
// virtual host.
func parseServerName(logger debuglog.Logger, authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		// missing port or bad format
		logger.Debug().
			Err(err).
			Msg("Failed to parse server name from authority")
		host = authority
	}
	return host
}
