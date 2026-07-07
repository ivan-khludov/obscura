package httpproxy

// SetParseProtocolDataHookForTest overrides ParseProtocolData during RenderInbound.
func SetParseProtocolDataHookForTest(fn func([]byte) (ProtocolData, error)) func() {
	old := parseProtocolDataHook
	parseProtocolDataHook = fn
	return func() { parseProtocolDataHook = old }
}

var parseProtocolDataHook func([]byte) (ProtocolData, error)

func parseProtocolDataForRender(raw []byte) (ProtocolData, error) {
	if parseProtocolDataHook != nil {
		return parseProtocolDataHook(raw)
	}
	return ParseProtocolData(raw)
}
