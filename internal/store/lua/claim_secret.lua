-- Consume a secret exactly once.
--
-- This is the only place a secret is burned, and it is the reason the whole
-- burn-on-read guarantee holds: Redis runs a script as a single atomic unit, so
-- no other command can slip between reading the state and writing it. A hundred
-- simultaneous reveals produce exactly one OK and ninety-nine LOST.
--
-- Expensive work deliberately happens outside this script. Argon2id key
-- derivation takes tens of milliseconds and Redis is single-threaded; doing it
-- in here would stall every other client. The caller derives the key, proves it
-- can unwrap the data key, and only then claims.
--
-- KEYS[1] secret hash
-- KEYS[2] receipt hash (may not exist)
-- ARGV[1] now, unix seconds
-- ARGV[2] tombstone TTL, seconds
-- ARGV[3] new state: consumed | burned | destroyed
--
-- Returns {'GONE'} | {'LOST', state} | {'OK', kind, ct, blob, meta_ct, psize}

local state = redis.call('HGET', KEYS[1], 'state')
if not state then
  return { 'GONE' }
end
if state ~= 'new' then
  return { 'LOST', state }
end

local data = redis.call('HMGET', KEYS[1], 'kind', 'ct', 'blob', 'meta_ct', 'psize')

redis.call('HSET', KEYS[1], 'state', ARGV[3], 'consumed_at', ARGV[1])
-- Drop everything needed to decrypt. What remains is a tombstone: enough to
-- tell the next visitor the link was already used, and nothing more.
redis.call('HDEL', KEYS[1], 'ct', 'wdek', 'salt', 'meta_ct', 'blob', 'kdfp')
redis.call('EXPIRE', KEYS[1], ARGV[2])

if redis.call('EXISTS', KEYS[2]) == 1 then
  redis.call('HSET', KEYS[2], 'state', ARGV[3], 'consumed_at', ARGV[1])
end

return { 'OK', data[1] or '', data[2] or '', data[3] or '', data[4] or '', data[5] or '0' }
