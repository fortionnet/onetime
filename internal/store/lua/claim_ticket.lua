-- Authorise one file download against a short-lived ticket.
--
-- The secret is already burned by the time a ticket exists, so the ticket only
-- has to survive a flaky network: a small number of retries is allowed inside
-- its five-minute life, but not an unbounded stream of them, which would turn
-- the service into a CDN for whoever holds the ticket.
--
-- KEYS[1] ticket hash
-- ARGV[1] max attempts
--
-- Returns {'GONE'} | {'EXHAUSTED'} | {'OK', blob, fname_ct, aad, psize}

if redis.call('EXISTS', KEYS[1]) == 0 then
  return { 'GONE' }
end

local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
if attempts > tonumber(ARGV[1]) then
  redis.call('DEL', KEYS[1])
  return { 'EXHAUSTED' }
end

local data = redis.call('HMGET', KEYS[1], 'blob', 'fname_ct', 'aad', 'psize')
return { 'OK', data[1] or '', data[2] or '', data[3] or '', data[4] or '0' }
