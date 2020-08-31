NetWitness Lua Parser implementing JA3 Hashing (https://github.com/salesforce/ja3)

# !!! This code is now DEPRECATED !!!
This is has now been replaced by an official Built-in implementation of JA3 and JA3S and should be considered deprecated. [JA3 and JA3S TLS Fingerprints (Towards the bottom of the page)](https://community.rsa.com/docs/DOC-80216)

Also there are a few interesting blog posts on the subject.

* [Contextualizing JA3 Fingerprints](https://community.rsa.com/community/products/netwitness/blog/2019/10/14/contextualizing-ja3-fingerprints)
* [Using RSA NetWitness to Detect Command and Control: PoshC2 v5.0](https://community.rsa.com/community/products/netwitness/blog/2019/12/02/using-rsa-netwitness-to-detect-command-and-control-poshc2-v50)
* Download feed from [ja3er.com](https://ja3er.com/) to CSV (For NW Feed Creation)

```curl -s -k https://ja3er.com/getAllUasJson -o -| jq -r '(map(keys) | add | unique) as $cols | map(. as $row | $cols | map($row[.])) as $rows | $cols, $rows[] | @csv' | sed -e 's/"$//g' | sed -e 's/,"md5/,md5/g' | sed -e 's/,"\([a-f0-9]*\)$/,\1/' | sed -e 's/,"\([^",]*\)",/,\1,/g' | sed -e 's/,"\([^",]*\)",/,\1,/g' > /var/netwitness/common/repo/ja3feed.csv```
