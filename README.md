# Diane

Diane is a fuzzer for IoT devices. Diane works by identifying *fuzzing triggers* in the IoT companion apps to produce valid yet under-constrained inputs.
Our key observation is that there exist functions inside the companion apps that are executed before any data-transforming functions (e.g., network serialization), but *after* the input validation code.

## Repository structure

Code and data will be released soon!

## Research paper

We present our approach and the findings of this work in the following research paper:

**DIANE: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices** 
[[PDF]](https://conand.me/publications/redini-diane-2021.pdf)  
Nilo Redini, Andrea Continella, Dipanjan Das, Giulio De Pasquale, Noah Spahn, Aravind Machiry, Antonio Bianchi, Christopher Kruegel, Giovanni Vigna.  
*In Proceedings of the IEEE Symposium on Security & Privacy (S&P), May 2021*

If you use *Diane* in a scientific publication, we would appreciate citations using this **Bibtex** entry:
``` tex
@inproceedings{redini_diane_21,
 author = {Nilo Redini and Andrea Continella and Dipanjan Das and Giulio De Pasquale and Noah Spahn and Aravind Machiry and Antonio Bianchi and Christopher Kruegel and Giovanni Vigna},
 booktitle = {In Proceedings of the IEEE Symposium on Security & Privacy (S&P)},
 month = {May},
 title = {{DIANE: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices}},
 year = {2021}
}
```
