sed 's/timestamp/placeholder123/g' $1 > temp1.ipal
python deletion.py temp1.ipal temp2.ipal temp3.json
sed 's/placeholder123/timestamp/g' temp2.ipal > $2
sed 's/placeholder123/timestamp/g' temp3.json > $3
rm temp1.ipal temp2.ipal temp3.json