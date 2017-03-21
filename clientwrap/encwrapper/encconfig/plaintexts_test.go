package encconfig

var plaintext1 = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")
var plaintext2 = []byte("Short text")
var plaintext3 = []byte("With non printables and nulls \x10 \x03 \x00 end string")
var plaintexts = [][]byte{plaintext1, plaintext2, plaintext3}
