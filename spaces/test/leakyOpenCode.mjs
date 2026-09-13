// What OpenCode's /config and /config/providers answer with — shaped from opencode 1.18 as measured, with a SECRET planted
// in every place a credential can sit (a stored key, provider and model options and headers, an MCP environment, a URL).
// Shared by codeRelay.test.mjs (the projection) and tools/opencode-connector.test.mjs (end to end through the connector).
export const LEAKY_PROVIDERS = {
  providers: [
    { id: 'anthropic', name: 'Anthropic', source: 'api', env: ['ANTHROPIC_API_KEY'], key: 'SECRET-sk-ant-key', options: { apiKey: 'SECRET-opt', headers: { authorization: 'SECRET-hdr' } },
      models: { 'claude-sonnet-4-6': { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6', status: 'active', providerID: 'anthropic', headers: { 'x-api-key': 'SECRET-mhdr' }, options: { apiKey: 'SECRET-mopt' }, api: { id: 'claude-sonnet-4-6', url: 'https://SECRET-url', npm: '@ai-sdk/anthropic' },
        capabilities: { toolcall: true, input: { text: true, image: true, pdf: true, audio: false, video: false } } } } },
    { id: 'trustedrouter', name: 'TrustedRouter', source: 'config', key: 'SECRET-tr-key',
      models: { 'deepseek/deepseek-v4-flash': { name: 'DeepSeek V4 Flash', capabilities: { input: ['text'] } }, 'old/model': { name: 'Old', status: 'deprecated' }, __proto__x: {} } },
    { name: 'no id', key: 'SECRET-noid' },
  ],
  default: { anthropic: 'claude-sonnet-4-6', trustedrouter: 'deepseek/deepseek-v4-flash', bad: { key: 'SECRET-def' } },
}
export const LEAKY_CONFIG = {
  $schema: 'https://opencode.ai/config.json', model: 'trustedrouter/deepseek/deepseek-v4-flash',
  mcp: { github: { environment: { GITHUB_TOKEN: 'SECRET-mcp' } } },
  provider: { trustedrouter: { name: 'TrustedRouter', options: { baseURL: 'https://api.trustedrouter.com/v1', apiKey: 'SECRET-resolved' },
    models: { 'deepseek/deepseek-v4-flash': { name: 'DeepSeek V4 Flash', options: { apiKey: 'SECRET-m' } }, 'anthropic/claude-opus-5': {} } } },
}
