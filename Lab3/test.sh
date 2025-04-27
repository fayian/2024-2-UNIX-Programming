rm -f /tmp/_pub.pem /tmp/_msg.bin /tmp/_sig.bin
cat > /tmp/_pub.pem<<EOF
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAILamhh4aXszHBI25FFaRDEi2SBohmL2wkXKSHMlX38g=
-----END PUBLIC KEY-----
EOF
echo -n 'FLAG{g0t_sud0ku_so1ved_2o25!}|Sun Apr 20 03:09:34 2025|' > /tmp/_msg.bin
echo 'V4QBMQvO/MSGqLoell9X9cXTmicBMjxeQGzqz8LgHoQl2hT+h/WHUbyW9CYkWztCGMj8YrUbsnG0WtNrn27sDA==' | base64 -d > /tmp/_sig.bin
openssl pkeyutl -verify -pubin -inkey /tmp/_pub.pem -rawin -in /tmp/_msg.bin -sigfile /tmp/_sig.bin