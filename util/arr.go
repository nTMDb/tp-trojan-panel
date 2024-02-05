package util

func SplitArr[T any](arr []T, num int) [][]T {
	length := len(arr)
	if length <= num {
		return [][]T{arr}
	}

	quantity := (length + num - 1) / num
	segments := make([][]T, 0, quantity)

	for i := 0; i < quantity; i++ {
		end := (i + 1) * num
		if end > length {
			end = length
		}

		segment := arr[i*num : end]
		segments = append(segments, segment)
	}

	return segments
}

// ArraysEqualPrefix 以a为主
func ArraysEqualPrefix(a, b []string) bool {
	// 如果两个数组长度不相等，直接返回false
	if len(a) > len(b) {
		return false
	}
	// 遍历两个数组的元素，逐一比较它们的值
	for i, item := range a {
		if item != b[i] {
			return false
		}
	}
	return true
}

func ArrContainKeys(arr []string, keys []string) bool {
	for _, item := range keys {
		if !ArrContain(arr, item) {
			return false
		}
	}
	return true
}

func ArrContain(arr []string, key string) bool {
	for _, item := range arr {
		if item == key {
			return true
		}
	}
	return false
}
