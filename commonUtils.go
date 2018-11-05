package encryptTool

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func StringToMap(data string) (dataS map[string]string) {
	datas := make(map[string]string)
	splitData := strings.Split(data, "&")
	for _, v := range splitData {
		vd := strings.Split(v, "=")
		datas[vd[0]] = vd[1]
	}
	return datas
}

//获取当前年月日时分秒
func GetTrace() string {
	return time.Now().Format("20060102150405")
}

//获取当年年月日
func GetTimeFromymd() string {
	return time.Now().Format("20060102")
}

//获取当前时分秒

func GetTimeFromSec() string {
	return time.Now().Format("150405")
}

/**
  生成随机字符串
*/
func RandomString(lens int) string {
	now := time.Now()
	return MakeMd5(strconv.FormatInt(now.UnixNano(), 10))[:lens]
}

/**
  字符串md5
*/
func MakeMd5(str string) string {
	h := md5.New()
	io.WriteString(h, str)
	s := fmt.Sprintf("%x", h.Sum(nil))
	return s
}

/**
  获取当前时间戳
*/
func GetNowSec() int64 {
	return time.Now().Unix()
}

/**
  获取当前时间戳
*/
func Str2Sec(layout, str string) int64 {
	tm2, _ := time.ParseInLocation(layout, str, time.Local)
	return tm2.Unix()
}

/**
  获取当前时间
*/
func Sec2Str(layout string, sec int64) string {
	t := time.Unix(sec, 0)
	nt := t.Format(layout)
	return nt
}

// base64 加密
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64 解密
func base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

type mapSorter []sortItem

type sortItem struct {
	Key string      `json:"key"`
	Val interface{} `json:"val"`
}

func (ms mapSorter) Len() int {
	return len(ms)
}
func (ms mapSorter) Less(i, j int) bool {
	return ms[i].Key < ms[j].Key // 按键排序
}
func (ms mapSorter) Swap(i, j int) {
	ms[i], ms[j] = ms[j], ms[i]
}
func mapSortByKey(m map[string]string, step1, step2 string) string {
	ms := make(mapSorter, 0, len(m))

	for k, v := range m {
		ms = append(ms, sortItem{k, v})
	}
	sort.Sort(ms)
	s := []string{}
	for _, p := range ms {
		s = append(s, p.Key+step1+p.Val.(string))
	}
	return strings.Join(s, step2)
}
func timeoutClient() *http.Client {
	connectTimeout := time.Duration(20 * time.Second)
	readWriteTimeout := time.Duration(30 * time.Second)
	return &http.Client{
		Transport: &http.Transport{
			Dial:                timeoutDialer(connectTimeout, readWriteTimeout),
			MaxIdleConnsPerHost: 200,
			DisableKeepAlives:   true,
		},
	}
}
func timeoutDialer(cTimeout time.Duration,
	rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, nil
	}
}

// urlencode
func Http_build_query(params map[string]string) string {
	qs := url.Values{}
	for k, v := range params {
		qs.Add(k, v)
	}
	return qs.Encode()
}
