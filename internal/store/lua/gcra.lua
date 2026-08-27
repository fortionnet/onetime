-- GCRA (generic cell rate algorithm) rate limiter: a leaky bucket that needs
-- one string per bucket and one round trip per check.
--
-- Preferred over a fixed window because a fixed window lets a client spend its
-- whole budget at the end of one window and again at the start of the next,
-- which is twice the intended rate at exactly the moment an attacker wants it.
-- Preferred over a sorted-set sliding log because that grows with traffic.
--
-- The clock is passed in rather than read via redis.call('TIME'), which keeps
-- the script deterministic and therefore safe to replicate.
--
-- KEYS[1] bucket
-- ARGV[1] now, milliseconds
-- ARGV[2] emission interval in ms (one permitted request every this often)
-- ARGV[3] burst capacity in ms (how far ahead of schedule a client may run)
--
-- Returns {allowed 0|1, retry_after_seconds}

local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])

-- Theoretical arrival time: the earliest moment the next request is due.
local tat = tonumber(redis.call('GET', KEYS[1])) or now
local allow_at = tat - burst

if now < allow_at then
  return { 0, math.ceil((allow_at - now) / 1000) }
end

local new_tat = math.max(tat, now) + interval
redis.call('SET', KEYS[1], new_tat, 'PX', math.ceil(new_tat - now + burst))
return { 1, 0 }
