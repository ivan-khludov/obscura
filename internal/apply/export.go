package apply

// ConfigPathForTest exposes the resolved config path for external tests.
func (p *Pipeline) ConfigPathForTest() string {
	return p.configPath
}
