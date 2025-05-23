package redis

import "github.com/gomodule/redigo/redis"

type setRds struct {
}

// 	添加元素
func (h *setRds) SAdd(key string, fileds []interface{}) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sadd", redis.Args{}.Add(key).AddFlat(fileds)...))
}

// 集合元素个数
func (h *setRds) SCard(key string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("scard", key))
}

// 返回集合中成员
func (h *setRds) SMembers(key string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("smembers", key))
}

// 判断元素是否是集合成员
func (h *setRds) SisMember(key string, member interface{}) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sismember", key, member))
}

// 随机返回并移除一个元素
func (h *setRds) SPop(key string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("spop", key))
}

// 随机返回一个或多个元素
func (h *setRds) SRandMember(key string, count ...int64) *Reply {
	conn := pool.Get()
	defer conn.Close()
	if len(count) > 0 {
		return getReply(conn.Do("srandmember", key, count[0]))
	}
	return getReply(conn.Do("srandmember", key))
}

// 移除指定的元素
func (h *setRds) SRem(key string, members []interface{}) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("srem", redis.Args{}.Add(key).AddFlat(members)...))
}

// 将元素从集合移至另一个集合
func (h *setRds) SMove(sourceKey, destinationKey string, member interface{}) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("smove", sourceKey, destinationKey, member))
}

//  返回一或多个集合的差集
func (h *setRds) SDiff(keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sdiff", redis.Args{}.AddFlat(keys)...))
}

// 将一或多个集合的差集保存至另一集合(destinationKey)
func (h *setRds) SDiffStore(destinationKey string, keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sdiffstore", redis.Args{}.Add(destinationKey).AddFlat(keys)...))
}

// 将keys的集合的并集 写入到 destinationKey中
func (h *setRds) SInterStore(destinationKey string, keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sinterstore", redis.Args{}.Add(destinationKey).AddFlat(keys)...))
}

// 一个或多个集合的交集
func (h *setRds) SInter(keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sinter", redis.Args{}.AddFlat(keys)...))
}

// 返回集合的并集
func (h *setRds) SUnion(keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sunion", redis.Args{}.AddFlat(keys)...))
}

// 将 keys 的集合的并集 写入到 destinationKey 中
func (h *setRds) SUnionStore(destinationKey string, keys []string) *Reply {
	conn := pool.Get()
	defer conn.Close()
	return getReply(conn.Do("sunionstore", redis.Args{}.Add(destinationKey).AddFlat(keys)...))
}
