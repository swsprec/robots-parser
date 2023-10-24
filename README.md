```

usage: robotsParser.py [-h] -f ROBOTSIN [-s SPECIALRULES] [-o OUTSTREAM]
                       [-i | --inplace | --no-inplace] [--robots-class RCLASS]
                       [--empty-class ECLASS]
                       [--non-empty-non-robots-class NENRCLASS]
                       [--non-empty-non-robots-threshold-class TCLASS]
                       [--unknown UCLASS]

optional arguments:
  -h, --help            show this help message and exit
  -f ROBOTSIN, --file ROBOTSIN
                        robots files input, or directory of robots files
  -s SPECIALRULES, --spec SPECIALRULES
                        file with special parsing rules for specific files
  -o OUTSTREAM, --output OUTSTREAM
                        file to append to with json, default is printing to
                        stdout
  -i, --inplace, --no-inplace
                        inplace file output mode, if activated, will output a
                        file in place with .json extension (default: False)
  --robots-class RCLASS
                        output file to store files that are most likely robots
                        files
  --empty-class ECLASS  output file to store files that are most likely empty
  --non-empty-non-robots-class NENRCLASS
                        output file to store files that are most likely not
                        robots files
  --non-empty-non-robots-threshold-class TCLASS
                        output file to store files that are most likely not
                        robots files via threshold
  --unknown UCLASS      output file to store files that are not classifiable
                        for further inquiry

```

