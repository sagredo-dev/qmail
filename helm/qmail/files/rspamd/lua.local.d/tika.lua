--[[
tika.lua — Apache Tika text extraction for rspamd
Sends binary attachments (PDF, DOCX, …) to Tika's REST API and registers
a TIKA_EXTRACTED symbol so the extracted text is visible in scan results.

Settings are hardcoded below; adjust and rebuild the stack to change them.
Fail-open: if Tika is unreachable or returns an error the symbol is simply
not set — mail flows through without penalty.
]]--

local rspamd_logger = require 'rspamd_logger'
local rspamd_http   = require 'rspamd_http'
local lua_util      = require 'lua_util'

local N = 'tika'

local settings = {
  url     = 'http://tika:9998',
  timeout = 15.0,
  mime_types = {
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/rtf',
    'text/html',
  },
}

-- Build a set for O(1) lookup
local mime_set = {}
for _, mt in ipairs(settings.mime_types) do
  mime_set[mt] = true
end

rspamd_logger.infox(rspamd_config, '%s: loaded, url=%s', N, settings.url)

local SYM_EXTRACTED = 'TIKA_EXTRACTED'

-- Register callback first, capture ID for virtual child reference
local cb_id = rspamd_config:register_symbol({
  name     = N .. '_CHECK',
  type     = 'callback',
  score    = 0.0,
  group    = 'tika',
  callback = function(task)
    local parts = task:get_parts()
    if not parts then return false end

    local pending = 0

    for _, part in ipairs(parts) do
      if part:is_attachment() then
        local mtype, msubtype = part:get_type()
        if mtype and msubtype then
          local full_type = mtype .. '/' .. msubtype
          if mime_set[full_type] then
            local content = part:get_content()
            if content and #content > 0 then
              pending = pending + 1

              local cap_type = full_type
              local cap_size = #content

              rspamd_http.request({
                task    = task,
                url     = settings.url .. '/tika',
                method  = 'PUT',
                body    = content,
                headers = {
                  ['Content-Type'] = full_type,
                  ['Accept']       = 'text/plain',
                },
                timeout  = settings.timeout,
                callback = function(err, code, body, _)
                  pending = pending - 1
                  if err then
                    lua_util.debugm(N, task, 'tika unavailable: %s', err)
                  elseif code == 200 and body and #body > 0 then
                    task:insert_result(SYM_EXTRACTED, 1.0,
                        cap_type .. '(' .. #body .. 'b)')
                    rspamd_logger.infox(task,
                        '%s: extracted %d bytes of text from %s (%d byte attachment)',
                        N, #body, cap_type, cap_size)
                  else
                    lua_util.debugm(N, task, 'tika HTTP %d for %s',
                        code or 0, cap_type)
                  end
                end,
              })
            end
          end
        end
      end
    end

    return pending > 0
  end,
})

-- Virtual symbol — registered after parent
rspamd_config:register_symbol({
  name        = SYM_EXTRACTED,
  type        = 'virtual',
  parent      = cb_id,
  score       = 0.0,
  group       = 'tika',
  description = 'Tika extracted text from a binary attachment',
})
