package encryptTool

type Hash uint

const (
	MD4     Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                     // import crypto/md5
	SHA1                    // import crypto/sha1
	SHA224                  // import crypto/sha256
	SHA256                  // import crypto/sha256
	SHA384                  // import crypto/sha512
	SHA512                  // import crypto/sha512
	MD5SHA1                 // no implementation; MD5+SHA1 used for TLS RSA
)
