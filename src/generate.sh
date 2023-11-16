SERVICE="oauth"

# find ./ -name '*[^.x]' -delete
make -f "Makefile.$SERVICE" clean

# Override the current makefile
rm -f "Makefile.$SERVICE"
rpcgen -NC "$SERVICE.x"
cp "../valid_makefile" "Makefile.$SERVICE"

cp -r "../tests" ./
cp "../check.sh" ./

# make -f "Makefile.$SERVICE"