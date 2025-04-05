package core

type ParamExtractor interface {
	GetParam(key string) string
}
