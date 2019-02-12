# build envoy
pushd ..
    bazel build //source/exe:envoy --verbose_failures
popd

# start envoy. set file secret provider and provide configure to speak to mysql:3306 on 9903
# also specify dynamic linking path for secretlesslib
LD_LIBRARY_PATH=$PWD/../source/extensions/filters/network/mysql_proxy
  DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH \
  SECRET_PROVIDER=file \
  ../bazel-bin/source/exe/envoy-static --config-yaml "$(cat config-mysql.yml)"

# start mysql
docker run --name mysql-test --rm -e MYSQL_ROOT_PASSWORD=securerootpass -p 3306:3306 -d mysql/mysql-server:5.7

#wait for mysql
docker exec -it mysql-test  bash -c "
echo 'Waiting for MySQL to start'
while ! mysqladmin -psecurerootpass status > /dev/null 2>&1;
do
  >&2 printf '. '
  sleep 1
done

echo ''
>&2 echo 'MySQL is up - continuing'
"

# create a user that can login using password from any host
docker exec -it mysql-test mysql -uroot -psecurerootpass -e "CREATE USER 'kumbi'@'%' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON * . * TO 'kumbi'@'%';"

# access mysql via envoy using secret provider (notice client is given gibberish credentials)
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u kxmbi -ppxssword -e "status"

# inspect the container logs and see that secretless is in the mix:
# [2019-02-12 01:51:03.516][1295323][info][filter] [source/extensions/filters/network/mysql_proxy/mysql_filter.cc:38] requestingAuth
# 2019/02/12 01:51:03 Instantiating provider 'file'
# 2019/02/12 01:51:03 Instantiating provider 'file'
#

# modify db-username or db-password
printf "wrong-password" > db-password

# failed access
docker exec -it mysql-test mysql -h host.docker.internal -P 9903 --ssl=FALSE -u kxmbi -ppxssword -e "status"
