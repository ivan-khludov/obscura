package service

import "github.com/ivan-khludov/obscura/internal/protocol"

// buildProtocolDataPreview assembles protocol or input data from create parameters.
func (s *Service) buildProtocolDataPreview(in CreateVPNInput, tag string) ([]byte, error) {
	return s.buildProtocolData(in, tag, protocol.BuildModePreview)
}
