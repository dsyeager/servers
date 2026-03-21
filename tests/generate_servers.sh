for ((i=1,a=10,b=1;i<=$1;i++,b++));do
   if [ "$b" -gt 255 ]; then
       ((a++));
       b=1;
   fi
   echo "192.168."$a"."$b" myhost"$i".com"
   # fe80::223:24ff:fed8:<i hex value>
   echo "fe80::223:24ff:fed8:1 myhost"$i".com"
done

