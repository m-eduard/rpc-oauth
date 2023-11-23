SERVICE="oauth"

# find ./ -name '*[^.x]' -delete
make -f "makefile" clean

# Override the current makefile
rm -f "Makefile.$SERVICE"
rpcgen -NC "$SERVICE.x"
cp "../valid_makefile" "makefile"

cp -r "../tests" ./
cp "../check.sh" ./

# make -f "makefile"