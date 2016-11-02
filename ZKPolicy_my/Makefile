flag = "-I /usr/local/include/zookeeper/ /usr/local/lib/libzookeeper_mt.so -lm -g -w "
object = policyWather.o cJSON.o utility.o parse.o
policyWatch:$(object)
gcc -o policyWatch $(flag) $(object)

$(object):

#policyWatch.o:policyWatch.h 
#    gcc policyWatcher.c -I /usr/local/include/zookeeper/ /usr/local/lib/libzookeeper_mt.so cJSON.c utility.c parse.c -lm -g -w -o  policyWatcher
