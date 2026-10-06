package netdisk115

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeUploadTokenVectors(t *testing.T) {
	assert.Equal(t, "adfe04b9f988d50207faa923f906f575", uploadToken(123456, 1700000000, 4097, "0123456789ABCDEF0123456789ABCDEF01234567", "", "37.3.1"))
	assert.Equal(t, "c28a362a61b4ed82846bb039803aec54", uploadToken(123456, 1700000000, 4097, "0123456789ABCDEF0123456789ABCDEF01234567", "synthetic-keyABCDEF0123456789ABCDEF0123456789ABCDEF01", "37.3.1"))
	assert.Equal(t, "1489a9b183f89c849338c803a60cafa6", uploadToken(123456, 1700000000, 4097, "0123456789ABCDEF0123456789ABCDEF01234567", "", ""))
	assert.Equal(t, "8fb3bd2097b7b8f4f49dd6fc8f281cdf", uploadToken(123456, 1700000000, 4097, "0123456789ABCDEF0123456789ABCDEF01234567", "synthetic-keyABCDEF0123456789ABCDEF0123456789ABCDEF01", ""))
}
func TestECZeroPaddingVectors(t *testing.T) {
	var ctx ecContext
	for i := range ctx.secret {
		ctx.secret[i] = byte(i)
	}
	{
		decoded, err := ctx.encrypt([]byte("p"))
		require.NoError(t, err)
		assert.Equal(t, "65544b428b2ef3509146af15504f67a4", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthe"))
		require.NoError(t, err)
		assert.Equal(t, "7c76bb7f01352f05078855828f29a315", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthet"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e61", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-syntheti"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e614845f7344bbecbe93415c46d70835254", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthetic-data-protoco"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e61027503bcd5778180d2793d690b77a831", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthetic-data-protocol"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e619d2b8af40132145341b5486e3421c7a8", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthetic-data-protocol-"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e619d2b8af40132145341b5486e3421c7a88f1a59dcc3c3d7ca4ed521d3bda2f104", hex.EncodeToString(decoded))
	}
	{
		decoded, err := ctx.encrypt([]byte("protocol-synthetic-data-protocol-synthetic-data-protocol-synthetic-data-protocol-synthetic-data-protocol-synthetic-data-protocol-"))
		require.NoError(t, err)
		assert.Equal(t, "05f163676c33c58c23dd43855de50e619d2b8af40132145341b5486e3421c7a87df43d250c22e73993d46297fb4b21c983209c87a24d717ecc8e28b1602e39050ec26180fe62045f6b476b950bca6b95abcef8730e4ad4b5791b70cd16033215850b5ab550bb25124a60dfc59df00a5767c79a726ad55e706a853d0d3e6d30db4a032c9b9b6f60cb719f3087fca09d7e", hex.EncodeToString(decoded))
	}
}
func TestECQueryIdentityAndCRC(t *testing.T) {
	var ctx ecContext
	token := ctx.queryToken(123456, time.Unix(1700000000, 123000000))
	raw, err := base64.StdEncoding.DecodeString(token)
	require.NoError(t, err)
	require.Len(t, raw, 48)
	assert.Equal(t, crc32.ChecksumIEEE(append([]byte(ecSalt), raw[:44]...)), binary.LittleEndian.Uint32(raw[44:]))
	for i := 16; i < 24; i++ {
		raw[i] ^= raw[15]
	}
	assert.Equal(t, uint32(123456), binary.LittleEndian.Uint32(raw[16:20]))
	assert.Equal(t, uint32(1700000000), binary.LittleEndian.Uint32(raw[20:24]))
}
func TestM115NativeResponseVectors(t *testing.T) {
	{
		decoded, err := m115Decode("byoYqo15eEMHhksDdDilTZ4TzclkBbxIF55LDkXupUhaOqGRpXRpiza/hO5zeLO7W/hmie1gldSX3sVyo4/CS17K397U69gB/c3Z1CUwe67cUQ2rf8CvIFatpvxDjl5Zz8nZBWcSMwDvbExlXFEOYSU1DoJBpXsjJ7J7XXzauco=", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "s", string(decoded))
	}
	{
		decoded, err := m115Decode("WvdCWjsPusmphchlPrLxL8uHpZ8TOAKGespaPIJVYdxcSHAuWYajVtSdogbv/Zk5NTEOc240gfKXekZYeik0C2K3F5/mcGVOCqv6RzVZnd03ScHlpp6HfOx1X7IdZYcseDr8V0NYPssPYTzVHXtN38ia0Em1SzVrdNUnb43YioI=", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "syn", string(decoded))
	}
	{
		decoded, err := m115Decode("PMlSZ6Qg6XTsQ+lkxTZIhCaVYvXJmWA8zIQJCYpxMwaQCMoFdnuFztNRwdfjY2v2LGgElx29kWv3JySkIQ5QtV1eltg1TrmDp5bCTrVndvEk6X+GNtaWueA7MvKzwXutOmJSNENkgimxz/PTByW9DkJrktRqWhWFWhR/WVVPKpQ=", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synt", string(decoded))
	}
	{
		decoded, err := m115Decode("cPOg943xZ6IlIkSNXj9C5MVQQLQ+iX0AaAIIFNL3vkMwuV7T/Ygkhg6YPB6j40BvmPWeAxLh95pNTE9Khfi5EBmr5Tp6tXrcKxSJVV+Kw2+OWVFI2Bl2Y96rJMKV8SjfzEwyL6j152jzuBeIHlpkqBNWsZWZJdhJxq2sLiuJL9A=", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protoco", string(decoded))
	}
	{
		decoded, err := m115Decode("cTJ8xqKD0BwBDbeVLoVPkb5RIc2zixqtOG6qKZ/xRlmxk63TfCBl/aEbmcZDMqJ2uS2vmZ/Ll/RnveVpbCF/N8kPm81B1++ipsBe5h+BidXCZs6jOeDo+Gq6lJHOmnBzIXG+ffXekA5BG0BNVg0iZhqnt9S4wZKf3mcuNObQeJpb5CkGlZlziVNprmuKPUyFjI2eCTUV6XyLQfA18nGtK5yPi9CyvB4bDGY42rDIyLOx6mBBxQrBpmwYc+PfOBUemb1mVwtKAFv1QTpGPkkRde8cuTj9yc/CAD9mnAe1XIpgIh2UGjWalULVuA230foge1mwtyK7Fr6Iv5I11GPnYg==", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-sy", string(decoded))
	}
	{
		decoded, err := m115Decode("dQ36g+gZx8ykMVslCxFIEEXJHkWlGoaNdC6JbCPkBDvZMRGjaNKLGZFfNFiPcvSNPJcoR3wiD7Gcs/TS9CXH/yBKzHkQTfhRjSL4NoHZyzwc0RdAniJnwf2RGIIm4vz6vN4i03e02847O5/gpHfVA2azv+qIRyC4ZCsZxIo/SwgigJlk7pxTl/cycjA2mp4rPmyABv8qHkxDbhLLUEv1Tfo/EOUL7Z8eRuVdyowhBvn4kHoR/LUKdVcjE18qu0ALzi4pb94HPoV0k8VZ2goAh0egjIbRmnJ+/2kpKS7yDsgflEHK2jwLNTPtGXSL0Ux/+0M1cmG6xDKKjEVOR3iZOQ==", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-syn", string(decoded))
	}
	{
		decoded, err := m115Decode("cxOICiMskQdetTMQUg4nWt/st5usOk5Tu56K4JpTbNZa5OE/QO4OH4i3H9lK28Y66GUwajJukbwGhFwYqrzB3ZO4ZlgcEeX5w//OAkYRmWo2W/gaJSdCyVkeoS4XeJSvj5MRCzSOmILGI1nNnJd2uEYqyTW+BqA6hYKuWHq9S+xyxNaDOpTkRhRO+UtK2HZvNSpr1/SVGk/zygCiJk3IEDUUMKH+I6tbe6vrhyC5EgIhWTx3esqjG6FS0bWG88EPloP+u5thqnFWgT1gnuEAJkteBukCSEsGfCdondIG5FaMIgPqkre5mn7BajjXk/TRaxgT9e5fKZ3q88LBgzuaUw==", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synt", string(decoded))
	}
	{
		decoded, err := m115Decode("c+x64WNhvJtDo1mezf8s6M7df61bHgy1t9a8ynXAmXbNymk44bijxJFyNlIXfz9+LNZVC7f3/VOhYFI0wkcNOVTwEhGRCpzzWrOx+JAjefMr1FgfyRMWnRHed5+OVmU4d1BffpIkGEDaj42+hm2iGYOeWZgBHXDwJXNSYTELmwomuwHwfSTB9URw315zmVAQnRBnTACAlr5KBOSgHapxfyHB8gIhhqF/DicoMhVyrhxIl/wcXn+jYHL3CkMCgbFsR94DWyb+5Y3h1xlQGa2Lb0anyRoYB/ACstC2rBEMj3Hv4boZijCpEPsgbuBQroGL9eUKop/+EuTuRtZ9+4GqSg==", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-proto", string(decoded))
	}
	{
		decoded, err := m115Decode("KhzFsWH4W9xkkQp2TFAtnEZRQueI0g0qt+NRDEjZusU75nvuz77Gsg7eRFO2L5tPVod83subgL8r7Eih1Fn05WN5EvOdCP7X+GIFqvVjEU0V3BFoRtzwlzV+IsDb3sT7XRitAgLbl6eak68Zi+REKLnNyjIaTjeHvQIrmpwvsLEGN3+lsFi0kWYP1JFykdt4t4MYi4E2fN/qqDg86qZLd4donI4GGZp22noqJjrC9Y7BGG2Fwve1TehCgawY6D48rEB7MZuapa9N8SEY3tF9zMB+C/s8W0DcojRPGRyvESG4tA4FbZhhten/doSDldhOreMlChv/UjCzWEh/XM1Gw2Gib6MRB5XEv5iCLP4sa5uFJv+44ZL4nC3Ke1p0hKm+ZQdVBoWvmEiXT3T1VGON/YnuEIfG483ndNAow6yYCHQ0pZegm/lg/YieOU0bL6gLGPxSIO9WCPmCVg87wlwlw3TUQJ+Vt4zCl6jVK3S9uYKRDCye2KDc+3IiU2ZCv/+zTKbTMOQJfvXbRuDk3v12vy7b7/a0c8/g+bIJVBEXHdpc9Eqhqw4bULSrh/tdeW5EYDhAHvk2wjA8AK1FeuOedjOJYuWwUu6xzk8K1M61ZtJbr5kvrJ9SqsziTUikf88WfLFdwUvm6q1sM0Huvd/VT3q9Rrz6I474uz7WutIr0Yo7izpAoMKYtmeeFvmH5zEWU6Ak2eR1qad4lVA1rEerb3k3zTYNDGvSOPqMQFgJvvkRIhyl8GaPxmbmg34XvpiiMaYrbx+fnLs1g6EpVol9jaqVnPLSOmtDvlJGXQj0Q74M/ejmqubWSWpfAxg7ObNi64vKyVUlcjV04GgrWBERqQ==", []byte("0123456789abcdef"))
		require.NoError(t, err)
		assert.Equal(t, "synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protocol-synthetic-protoco", string(decoded))
	}
}
func TestMalformedControlPackets(t *testing.T) {
	var ctx ecContext
	for _, packet := range [][]byte{nil, {0}, {0, 1, 2}, make([]byte, 12)} {
		_, err := ctx.decode(packet)
		require.Error(t, err)
	}
	_, err := m115Decode("AAAA", []byte("0123456789abcdef"))
	require.Error(t, err)
}
