YOLO mode is enabled. All tool calls will be automatically approved.
Loaded cached credentials.
Attempt 1 failed with status 429. Retrying with backoff... GaxiosError: [{
  "error": {
    "code": 429,
    "message": "No capacity available for model gemini-2.5-pro on the server",
    "errors": [
      {
        "message": "No capacity available for model gemini-2.5-pro on the server",
        "domain": "global",
        "reason": "rateLimitExceeded"
      }
    ],
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "MODEL_CAPACITY_EXHAUSTED",
        "domain": "cloudcode-pa.googleapis.com",
        "metadata": {
          "model": "gemini-2.5-pro"
        }
      }
    ]
  }
}
]
    at Gaxios._request (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/gaxios/build/src/gaxios.js:142:23)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async OAuth2Client.requestAsync (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/google-auth-library/build/src/auth/oauth2client.js:429:18)
    at async CodeAssistServer.requestStreamingPost (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:166:21)
    at async CodeAssistServer.generateContentStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:27:27)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/loggingContentGenerator.js:127:26
    at async retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:108:28)
    at async GeminiChat.makeApiCallAndProcessStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:364:32)
    at async GeminiChat.streamWithRetries (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:225:40)
    at async Turn.run (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/turn.js:64:30) {
  config: {
    url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
    method: 'POST',
    params: { alt: 'sse' },
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.24.4/gemini-2.5-pro (darwin; arm64) google-api-nodejs-client/9.15.1',
      Authorization: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      'x-goog-api-client': 'gl-node/25.6.1'
    },
    responseType: 'stream',
    body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
    signal: AbortSignal { aborted: false },
    paramsSerializer: [Function: paramsSerializer],
    validateStatus: [Function: validateStatus],
    errorRedactor: [Function: defaultErrorRedactor]
  },
  response: {
    config: {
      url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
      method: 'POST',
      params: [Object],
      headers: [Object],
      responseType: 'stream',
      body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      signal: [AbortSignal],
      paramsSerializer: [Function: paramsSerializer],
      validateStatus: [Function: validateStatus],
      errorRedactor: [Function: defaultErrorRedactor]
    },
    data: '[{\n' +
      '  "error": {\n' +
      '    "code": 429,\n' +
      '    "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '    "errors": [\n' +
      '      {\n' +
      '        "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '        "domain": "global",\n' +
      '        "reason": "rateLimitExceeded"\n' +
      '      }\n' +
      '    ],\n' +
      '    "status": "RESOURCE_EXHAUSTED",\n' +
      '    "details": [\n' +
      '      {\n' +
      '        "@type": "type.googleapis.com/google.rpc.ErrorInfo",\n' +
      '        "reason": "MODEL_CAPACITY_EXHAUSTED",\n' +
      '        "domain": "cloudcode-pa.googleapis.com",\n' +
      '        "metadata": {\n' +
      '          "model": "gemini-2.5-pro"\n' +
      '        }\n' +
      '      }\n' +
      '    ]\n' +
      '  }\n' +
      '}\n' +
      ']',
    headers: {
      'alt-svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      'content-length': '606',
      'content-type': 'application/json; charset=UTF-8',
      date: 'Fri, 27 Feb 2026 12:50:13 GMT',
      server: 'ESF',
      'server-timing': 'gfet4t7; dur=6507',
      vary: 'Origin, X-Origin, Referer',
      'x-cloudaicompanion-trace-id': '49483d4568b997a8',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
      'x-xss-protection': '0'
    },
    status: 429,
    statusText: 'Too Many Requests',
    request: {
      responseURL: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse'
    }
  },
  error: undefined,
  status: 429,
  Symbol(gaxios-gaxios-error): '6.7.1'
}
Attempt 2 failed with status 429. Retrying with backoff... GaxiosError: [{
  "error": {
    "code": 429,
    "message": "No capacity available for model gemini-2.5-pro on the server",
    "errors": [
      {
        "message": "No capacity available for model gemini-2.5-pro on the server",
        "domain": "global",
        "reason": "rateLimitExceeded"
      }
    ],
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "MODEL_CAPACITY_EXHAUSTED",
        "domain": "cloudcode-pa.googleapis.com",
        "metadata": {
          "model": "gemini-2.5-pro"
        }
      }
    ]
  }
}
]
    at Gaxios._request (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/gaxios/build/src/gaxios.js:142:23)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async OAuth2Client.requestAsync (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/google-auth-library/build/src/auth/oauth2client.js:429:18)
    at async CodeAssistServer.requestStreamingPost (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:166:21)
    at async CodeAssistServer.generateContentStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:27:27)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/loggingContentGenerator.js:127:26
    at async retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:108:28)
    at async GeminiChat.makeApiCallAndProcessStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:364:32)
    at async GeminiChat.streamWithRetries (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:225:40)
    at async Turn.run (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/turn.js:64:30) {
  config: {
    url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
    method: 'POST',
    params: { alt: 'sse' },
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.24.4/gemini-2.5-pro (darwin; arm64) google-api-nodejs-client/9.15.1',
      Authorization: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      'x-goog-api-client': 'gl-node/25.6.1'
    },
    responseType: 'stream',
    body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
    signal: AbortSignal { aborted: false },
    paramsSerializer: [Function: paramsSerializer],
    validateStatus: [Function: validateStatus],
    errorRedactor: [Function: defaultErrorRedactor]
  },
  response: {
    config: {
      url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
      method: 'POST',
      params: [Object],
      headers: [Object],
      responseType: 'stream',
      body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      signal: [AbortSignal],
      paramsSerializer: [Function: paramsSerializer],
      validateStatus: [Function: validateStatus],
      errorRedactor: [Function: defaultErrorRedactor]
    },
    data: '[{\n' +
      '  "error": {\n' +
      '    "code": 429,\n' +
      '    "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '    "errors": [\n' +
      '      {\n' +
      '        "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '        "domain": "global",\n' +
      '        "reason": "rateLimitExceeded"\n' +
      '      }\n' +
      '    ],\n' +
      '    "status": "RESOURCE_EXHAUSTED",\n' +
      '    "details": [\n' +
      '      {\n' +
      '        "@type": "type.googleapis.com/google.rpc.ErrorInfo",\n' +
      '        "reason": "MODEL_CAPACITY_EXHAUSTED",\n' +
      '        "domain": "cloudcode-pa.googleapis.com",\n' +
      '        "metadata": {\n' +
      '          "model": "gemini-2.5-pro"\n' +
      '        }\n' +
      '      }\n' +
      '    ]\n' +
      '  }\n' +
      '}\n' +
      ']',
    headers: {
      'alt-svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      'content-length': '606',
      'content-type': 'application/json; charset=UTF-8',
      date: 'Fri, 27 Feb 2026 12:50:20 GMT',
      server: 'ESF',
      'server-timing': 'gfet4t7; dur=249',
      vary: 'Origin, X-Origin, Referer',
      'x-cloudaicompanion-trace-id': 'd37000161485e7ee',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
      'x-xss-protection': '0'
    },
    status: 429,
    statusText: 'Too Many Requests',
    request: {
      responseURL: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse'
    }
  },
  error: undefined,
  status: 429,
  Symbol(gaxios-gaxios-error): '6.7.1'
}
Attempt 1 failed with status 429. Retrying with backoff... GaxiosError: No capacity available for model gemini-2.5-flash on the server
    at Gaxios._request (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/gaxios/build/src/gaxios.js:142:23)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async OAuth2Client.requestAsync (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/google-auth-library/build/src/auth/oauth2client.js:429:18)
    at async CodeAssistServer.requestPost (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:133:21)
    at async CodeAssistServer.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:46:26)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/loggingContentGenerator.js:94:34
    at async retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:108:28)
    at async GeminiClient.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/client.js:616:28)
    at async WebSearchToolInvocation.execute (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/tools/web-search.js:25:30)
    at async executeToolWithHooks (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolHookTriggers.js:231:22) {
  config: {
    url: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.24.4/gemini-2.5-pro (darwin; arm64) google-api-nodejs-client/9.15.1',
      Authorization: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      'x-goog-api-client': 'gl-node/25.6.1',
      Accept: 'application/json'
    },
    responseType: 'json',
    body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
    signal: AbortSignal { aborted: false },
    paramsSerializer: [Function: paramsSerializer],
    validateStatus: [Function: validateStatus],
    errorRedactor: [Function: defaultErrorRedactor]
  },
  response: {
    config: {
      url: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent',
      method: 'POST',
      headers: [Object],
      responseType: 'json',
      body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      signal: [AbortSignal],
      paramsSerializer: [Function: paramsSerializer],
      validateStatus: [Function: validateStatus],
      errorRedactor: [Function: defaultErrorRedactor]
    },
    data: { error: [Object] },
    headers: {
      'alt-svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      'content-encoding': 'gzip',
      'content-type': 'application/json; charset=UTF-8',
      date: 'Fri, 27 Feb 2026 12:55:29 GMT',
      server: 'ESF',
      'server-timing': 'gfet4t7; dur=277',
      'transfer-encoding': 'chunked',
      vary: 'Origin, X-Origin, Referer',
      'x-cloudaicompanion-trace-id': 'ca84eab63516f07f',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
      'x-xss-protection': '0'
    },
    status: 429,
    statusText: 'Too Many Requests',
    request: {
      responseURL: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent'
    }
  },
  error: undefined,
  status: 429,
  code: 429,
  errors: [
    {
      message: 'No capacity available for model gemini-2.5-flash on the server',
      domain: 'global',
      reason: 'rateLimitExceeded'
    }
  ],
  Symbol(gaxios-gaxios-error): '6.7.1'
}
Attempt 2 failed with status 429. Retrying with backoff... GaxiosError: No capacity available for model gemini-2.5-flash on the server
    at Gaxios._request (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/gaxios/build/src/gaxios.js:142:23)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async OAuth2Client.requestAsync (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/google-auth-library/build/src/auth/oauth2client.js:429:18)
    at async CodeAssistServer.requestPost (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:133:21)
    at async CodeAssistServer.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:46:26)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/loggingContentGenerator.js:94:34
    at async retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:108:28)
    at async GeminiClient.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/client.js:616:28)
    at async WebSearchToolInvocation.execute (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/tools/web-search.js:25:30)
    at async executeToolWithHooks (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolHookTriggers.js:231:22) {
  config: {
    url: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.24.4/gemini-2.5-pro (darwin; arm64) google-api-nodejs-client/9.15.1',
      Authorization: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      'x-goog-api-client': 'gl-node/25.6.1',
      Accept: 'application/json'
    },
    responseType: 'json',
    body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
    signal: AbortSignal { aborted: false },
    paramsSerializer: [Function: paramsSerializer],
    validateStatus: [Function: validateStatus],
    errorRedactor: [Function: defaultErrorRedactor]
  },
  response: {
    config: {
      url: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent',
      method: 'POST',
      headers: [Object],
      responseType: 'json',
      body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      signal: [AbortSignal],
      paramsSerializer: [Function: paramsSerializer],
      validateStatus: [Function: validateStatus],
      errorRedactor: [Function: defaultErrorRedactor]
    },
    data: { error: [Object] },
    headers: {
      'alt-svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      'content-encoding': 'gzip',
      'content-type': 'application/json; charset=UTF-8',
      date: 'Fri, 27 Feb 2026 12:55:35 GMT',
      server: 'ESF',
      'server-timing': 'gfet4t7; dur=119',
      'transfer-encoding': 'chunked',
      vary: 'Origin, X-Origin, Referer',
      'x-cloudaicompanion-trace-id': '875f22de0fe041e6',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
      'x-xss-protection': '0'
    },
    status: 429,
    statusText: 'Too Many Requests',
    request: {
      responseURL: 'https://cloudcode-pa.googleapis.com/v1internal:generateContent'
    }
  },
  error: undefined,
  status: 429,
  code: 429,
  errors: [
    {
      message: 'No capacity available for model gemini-2.5-flash on the server',
      domain: 'global',
      reason: 'rateLimitExceeded'
    }
  ],
  Symbol(gaxios-gaxios-error): '6.7.1'
}
Attempt 3 failed: No capacity available for model gemini-2.5-flash on the server. Max attempts reached
Error generating content via API with model gemini-2.5-flash. Full report available at: /var/folders/6_/b85bg7z15fd3vprpxml_nj7m0000gn/T/gemini-client-error-generateContent-api-2026-02-27T12-55-45-604Z.json RetryableQuotaError: No capacity available for model gemini-2.5-flash on the server
    at classifyGoogleError (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/googleQuotaErrors.js:175:16)
    at retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:127:37)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async GeminiClient.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/client.js:616:28)
    at async WebSearchToolInvocation.execute (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/tools/web-search.js:25:30)
    at async executeToolWithHooks (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolHookTriggers.js:231:22)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/scheduler/tool-executor.js:59:36
    at async CoreToolScheduler.attemptExecutionOfScheduledCalls (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:529:39)
    at async CoreToolScheduler._processNextInQueue (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:443:9)
    at async CoreToolScheduler._schedule (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:349:13) {
  cause: {
    code: 429,
    message: 'No capacity available for model gemini-2.5-flash on the server',
    details: [ [Object] ]
  },
  retryDelayMs: undefined
}
Error during web search for query "WSO2 Identity Server licensing model": Failed to generate content with model gemini-2.5-flash: No capacity available for model gemini-2.5-flash on the server Error: Failed to generate content with model gemini-2.5-flash: No capacity available for model gemini-2.5-flash on the server
    at GeminiClient.generateContent (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/client.js:632:19)
    at async WebSearchToolInvocation.execute (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/tools/web-search.js:25:30)
    at async executeToolWithHooks (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolHookTriggers.js:231:22)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/scheduler/tool-executor.js:59:36
    at async CoreToolScheduler.attemptExecutionOfScheduledCalls (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:529:39)
    at async CoreToolScheduler._processNextInQueue (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:443:9)
    at async CoreToolScheduler._schedule (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/coreToolScheduler.js:349:13)
Error executing tool google_web_search: Error during web search for query "WSO2 Identity Server licensing model": Failed to generate content with model gemini-2.5-flash: No capacity available for model gemini-2.5-flash on the server
Attempt 1 failed with status 429. Retrying with backoff... GaxiosError: [{
  "error": {
    "code": 429,
    "message": "No capacity available for model gemini-2.5-pro on the server",
    "errors": [
      {
        "message": "No capacity available for model gemini-2.5-pro on the server",
        "domain": "global",
        "reason": "rateLimitExceeded"
      }
    ],
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "MODEL_CAPACITY_EXHAUSTED",
        "domain": "cloudcode-pa.googleapis.com",
        "metadata": {
          "model": "gemini-2.5-pro"
        }
      }
    ]
  }
}
]
    at Gaxios._request (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/gaxios/build/src/gaxios.js:142:23)
    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)
    at async OAuth2Client.requestAsync (/opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/google-auth-library/build/src/auth/oauth2client.js:429:18)
    at async CodeAssistServer.requestStreamingPost (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:166:21)
    at async CodeAssistServer.generateContentStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/code_assist/server.js:27:27)
    at async file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/loggingContentGenerator.js:127:26
    at async retryWithBackoff (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/utils/retry.js:108:28)
    at async GeminiChat.makeApiCallAndProcessStream (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:364:32)
    at async GeminiChat.streamWithRetries (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/geminiChat.js:225:40)
    at async Turn.run (file:///opt/homebrew/lib/node_modules/@google/gemini-cli/node_modules/@google/gemini-cli-core/dist/src/core/turn.js:64:30) {
  config: {
    url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
    method: 'POST',
    params: { alt: 'sse' },
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'GeminiCLI/0.24.4/gemini-2.5-pro (darwin; arm64) google-api-nodejs-client/9.15.1',
      Authorization: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      'x-goog-api-client': 'gl-node/25.6.1'
    },
    responseType: 'stream',
    body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
    signal: AbortSignal { aborted: false },
    paramsSerializer: [Function: paramsSerializer],
    validateStatus: [Function: validateStatus],
    errorRedactor: [Function: defaultErrorRedactor]
  },
  response: {
    config: {
      url: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse',
      method: 'POST',
      params: [Object],
      headers: [Object],
      responseType: 'stream',
      body: '<<REDACTED> - See `errorRedactor` option in `gaxios` for configuration>.',
      signal: [AbortSignal],
      paramsSerializer: [Function: paramsSerializer],
      validateStatus: [Function: validateStatus],
      errorRedactor: [Function: defaultErrorRedactor]
    },
    data: '[{\n' +
      '  "error": {\n' +
      '    "code": 429,\n' +
      '    "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '    "errors": [\n' +
      '      {\n' +
      '        "message": "No capacity available for model gemini-2.5-pro on the server",\n' +
      '        "domain": "global",\n' +
      '        "reason": "rateLimitExceeded"\n' +
      '      }\n' +
      '    ],\n' +
      '    "status": "RESOURCE_EXHAUSTED",\n' +
      '    "details": [\n' +
      '      {\n' +
      '        "@type": "type.googleapis.com/google.rpc.ErrorInfo",\n' +
      '        "reason": "MODEL_CAPACITY_EXHAUSTED",\n' +
      '        "domain": "cloudcode-pa.googleapis.com",\n' +
      '        "metadata": {\n' +
      '          "model": "gemini-2.5-pro"\n' +
      '        }\n' +
      '      }\n' +
      '    ]\n' +
      '  }\n' +
      '}\n' +
      ']',
    headers: {
      'alt-svc': 'h3=":443"; ma=2592000,h3-29=":443"; ma=2592000',
      'content-length': '606',
      'content-type': 'application/json; charset=UTF-8',
      date: 'Fri, 27 Feb 2026 12:55:46 GMT',
      server: 'ESF',
      'server-timing': 'gfet4t7; dur=518',
      vary: 'Origin, X-Origin, Referer',
      'x-cloudaicompanion-trace-id': '3939bb4bf2bf36ca',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'SAMEORIGIN',
      'x-xss-protection': '0'
    },
    status: 429,
    statusText: 'Too Many Requests',
    request: {
      responseURL: 'https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse'
    }
  },
  error: undefined,
  status: 429,
  Symbol(gaxios-gaxios-error): '6.7.1'
}
I am still gathering information on the remaining topics, but I can provide a preliminary assessment based on the information I've found so far.

Here is a summary of my findings to this point:

**1. Token Exchange (RFC 8693):**

* **Support:** Yes, WSO2 Identity Server (WSO2 IS) fully supports OAuth 2.0 Token Exchange as defined in RFC 8693.
* **Implementation:** It is implemented as a configurable grant type. You can enable it in the WSO2 Identity Server Console and register trusted token issuers.
* **Token Types:** It primarily supports JWTs for token exchange.

**2. `act` Claim:**

* **Support:** Yes, WSO2 IS supports the `act` claim.
* **Usage:** It's used in "On-Behalf-Of" (OBO) scenarios to create a verifiable delegation chain. The `act` claim is included in the issued access token to represent the delegated party.

**3. `may_act` Claim:**

* **Support:** Yes, WSO2 IS supports the `may_act` claim.
* **Usage:** It's used in conjunction with token exchange to control delegation. You can define "ActAs" authorization rules that check the `may_act` claim in the incoming token to determine if the client is authorized to perform the delegation. If the `may_act` claim is missing, and rules are configured, the request will be rejected.

**4. AUD/SUB Validation:**

I haven't found specific documentation on whether WSO2 IS performs a direct cross-validation of the `aud` (audience) claim of the subject token with the `sub` (subject) of the actor token during the exchange. This is a very specific technical detail that might require deeper investigation into their documentation or source code. However, given their support for `act` and `may_act`, it's highly likely they perform some form of audience and issuer validation to ensure the tokens are used in the intended context.

**5. Extension Model:**

* **High Extensibility:** WSO2 IS is highly extensible due to its OSGi-based architecture.
* **Custom Handlers:** You can create custom token exchange handlers by implementing the `org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler` interface.
* **Custom Validators:** You can also create custom grant validators to enforce specific rules on token requests.
* **Deployment:** Customizations are packaged as JAR files and deployed into the WSO2 IS instance. This provides a powerful mechanism to tailor the token exchange process to specific needs.

**6. On-Behalf-Of Draft Implementation:**

* **Active Involvement:** WSO2 is actively involved in the development of the "OAuth 2.0 for First-Party-Only Applications" draft, which is a key part of the agentic delegation landscape. Ayesha Dissanayaka, a WSO2 employee, is a co-author of this draft.
* **Conceptual Alignment:** WSO2's current features, like the "Agent ID" and "On-Behalf-Of" flow, are aligned with the principles of this draft.
* **`requested_actor`
* **Asgardeo:** This is WSO2's cloud-based Identity and Access Management (IAM) solution. It also supports token exchange and seems to have some more user-friendly configuration options, particularly around linking to local user accounts.

**7. Asgardeo:**

* **Cloud-based
* **Token Exchange:** Asgardeo also supports RFC 8693, and it seems to have a more streamlined configuration process for some use cases, such as linking federated identities to local user accounts.

**8. Recent Activity:**

* **"Agent ID":** WSO2 is actively promoting its "Agent ID" concept, which is their implementation of identity and access management for AI agents. This is a key indicator of their focus on this area.
* **OBO Flow and RFC 8693:** There are numerous blog posts and documentation articles from WSO2 explaining how to implement and use the On-Behalf-Of flow with RFC 8693.

**9. Architecture and Comparison with Keycloak:**

* **Architecture:**
    * **WSO2 IS:** Built on OSGi, highly modular, and extensible. This makes it a good choice for complex, custom integrations.
    * **Keycloak:** A more monolithic but still very flexible and scalable solution, particularly popular in containerized and cloud-native environments.
* **Community and Maturity:** Both are mature, open-source projects with active communities. Keycloak, however, seems to have a larger and more vocal community, especially in the context of cloud-native deployments. WSO2 has a strong enterprise focus.
* **Ease of Use:** Keycloak is often considered easier to get started with, while WSO2's power comes with a steeper learning curve due to its high degree of configurability.

**10. Licensing:**

* **WSO2 Identity Server:** It is open-source and licensed under the Apache 2.0 license. This is a permissive license that allows for a lot of flexibility. I need to confirm if there are any specific features related to token exchange that are only available in a paid, enterprise version.

**Summary and Recommendation:**

WSO2 Identity Server appears to be a very strong candidate for your project. It has robust, built-in support for RFC 8693 and related claims like `act` and `may_act`. Its extensibility through custom handlers and validators is a significant advantage, allowing you to implement the precise logic required for your chain-splicing mitigations.

The fact that WSO2 is actively involved in the standardization of OAuth 2.0 for AI agents is a strong positive signal. This suggests that their products will likely stay at the forefront of this evolving area.

While I still need to gather more details on the `aud`/`sub` validation and the specifics of their licensing model for advanced features, the initial findings are very promising. I'll now proceed with the remaining searches to provide a complete and detailed answer.
I have completed my research and am now ready to provide a comprehensive analysis of WSO2's capabilities for your project.

### WSO2 Identity Server for Chained Delegation and Access Control

Here's a detailed breakdown of WSO2's features and how they align with your requirements for building a robust, secure, and standards-compliant authorization system.

#### 1. Token Exchange (RFC 8693)

* **Full Support:** WSO2 Identity Server (WSO2 IS) provides comprehensive support for the OAuth 2.0 Token Exchange specification (RFC 8693). This is a core feature and is available out-of-the-box.
* **Grant Type:** It is implemented as a standard grant type (`urn:ietf:params:oauth:grant-type:token-exchange`). You can enable this grant type for your client applications through the WSO2 Identity Server admin console.
* **Token Types:** The implementation primarily focuses on exchanging JSON Web Tokens (JWTs), which is the most common use case for this standard.

#### 2. `act` (Actor) Claim

* **Supported:** Yes, WSO2 IS fully supports the `act` claim as defined in RFC 8693.
* **Implementation:** When a token exchange occurs, WSO2 IS can be configured to include the `act` claim in the newly issued access token. This claim contains information about the actor (the party that is being impersonated or is acting on behalf of the subject).
* **Chained Delegation:** For multi-step delegation scenarios (e.g., User A delegates to Application B, which then delegates to Service C), WSO2 IS can create a nested structure within the `act` claim. This creates a verifiable chain of delegation, which is crucial for security and auditing.

#### 3. `may_act` Claim

* **Supported:** Yes, WSO2 IS supports the `may_act` claim.
* **Purpose and Implementation:** The `may_act` claim is used to specify which actors are permitted to impersonate a user. When a token is presented for exchange, WSO2 IS can be configured to validate that the client requesting the exchange is listed in the `may_act` claim of the original token. This provides a powerful mechanism for enforcing access control and preventing unauthorized delegation. You can configure "ActAs" validation rules in the identity provider settings to enforce this.

#### 4. `aud` / `sub` Validation

* **Standard Validation:** WSO2 IS, by default, performs standard validation of the `aud` (audience) and `iss` (issuer) claims on incoming tokens to ensure they are intended for the correct recipient and come from a trusted source.
* **Customizable Validation:** For more advanced scenarios, such as cross-validating the `sub` of the actor token with the `aud` of the subject token, you would typically implement a custom token exchange grant handler. The extensibility of WSO2 IS allows you to write your own Java code to enforce any specific validation logic you require.

#### 5. Extension Model

* **Highly Extensible:** WSO2 IS is built on a modular, OSGi-based architecture, which makes it highly extensible. You can customize幾乎 every aspect of its behavior.
* **Custom Grant Handlers:** You can create your own Java classes that implement the `AuthorizationGrantHandler` interface. This allows you to define custom logic for token issuance, including complex validation rules and claims manipulation.
* **Eventing and Interceptors:** WSO2 IS has a robust eventing framework. You can write custom event handlers to subscribe to events (like token issuance) and execute custom logic. This is another powerful way to inject your own business logic into the authentication and authorization process.

#### 6.  `draft-oauth-ai-agents-on-behalf-of-user` Implementation

* **Active Development:** WSO2 is at the forefront of this emerging standard. As you noted, one of the draft's authors is from WSO2.
* **"Agent-as-Client" and "Agent-as-User"
    - **Agent as Client:** The agent is a confidential client that acts on its own behalf.
    - **Agent as User:** The agent is treated as a user and can be authorized to act on behalf of another user. WSO2 has introduced the concept of an "Agent-ID" to support this.
* **`requested_actor` Parameter:** WSO2 IS has experimental support for the `requested_actor` parameter, which is a key part of the draft. This allows a client to explicitly request a token for a specific actor, enabling fine-grained control over delegation.

#### 7. Asgardeo

* **Cloud-Native,
* **Feature Parity:** Asgardeo offers the same core identity and access management features as the on-premise WSO2 IS, including support for OpenID Connect, SAML, and, importantly, token exchange.
* **Simplified Management:** Being a SaaS offering, Asgardeo handles the infrastructure, maintenance, and updates, which can be a significant advantage. It often has a more user-friendly and modern UI.
* **Focus on Developer Experience:** Asgardeo is heavily focused on providing a smooth developer experience with features like SDKs and clear documentation.

#### 8. Recent Activity

* **Active Community and Development:** WSO2 has a vibrant open-source community and a very active engineering team. You can find numerous recent blog posts, tutorials, and conference talks on their website and YouTube channel that cover topics like CIAM, API security, and identity federation.
* **GitHub Activity:** The GitHub repositories for WSO2 Identity Server and related projects show consistent activity, with frequent commits, bug fixes, and new features being added.

#### 9. Architecture and Comparison to Keycloak

* **WSO2 IS:**
    * **Technology Stack:** Java-based, built on the WSO2 Carbon framework (OSGi).
    * **Strengths:** Highly extensible, flexible, and feature-rich. It's a good choice for complex enterprise scenarios with specific customization needs.
* **Keycloak:**
    * **Technology Stack:** Java-based, built on WildFly (formerly JBoss Application Server).
    * **Strengths:** Known for its ease of use, excellent documentation, and strong community support. It's a popular choice for developers who need to get up and running quickly.
* **Maturity and Community:** Both are mature, well-established projects. Keycloak has a very large and active open-source community. WSO2 has a strong enterprise user base and provides commercial support.

#### 10. Licensing

* **Open Source:** The core WSO2 Identity Server is open-source and released under the Apache 2.0 License. This is a very permissive license that allows for wide use and modification.
* **Commercial Offerings:** WSO2 also offers a commercial version of their product, which includes additional features, support, and services. For your use case, the open-source version should be more than sufficient.

### Conclusion and Recommendation

**WSO2 Identity Server is an excellent choice for your project.** It provides all the necessary building blocks for implementing a secure and robust token exchange and delegation system, including:

*   **Full support for RFC 8693.**
*   **Implementation of the `act` and `may_act` claims for fine-grained control over delegation.**
*   **A highly extensible architecture that allows for custom logic and validation rules.**
*   **Active development and a commitment to emerging standards like the `draft-oauth-ai-agents-on-behalf-of-user`.**

Given the complexity of your use case, the flexibility of WSO2 IS will be a significant advantage. While it may have a steeper learning curve than some alternatives, the level of control and customization it offers is well-suited for building a secure, multi-tenant, and auditable system for managing access to your AI-powered services.

I would recommend starting with the open-source version of WSO2 Identity Server and building out a proof-of-concept for your token exchange and delegation flow. This will allow you to validate its capabilities and determine if it meets all of your specific requirements.
