
# Solution for Tom's Data Onion

[Tom's Data Onion](https://www.tomdalling.com/toms-data-onion/) is a programming puzzle from [Tom Dalling](https://www.tomdalling.com) that you can find here:

    https://www.tomdalling.com/toms-data-onion/

This project contains a possible solution implemented in Python 3. The puzzle consists of 6 Layers, which have to be decrypted one by one to encounter the encrypted next layer.


## About the code

Module `tomsdataonion.py` contains the puzzle solving code. Module `tomtelvm.py` contains some helper code for a certain layer. For each layer there is a function `peelN()` to handle that layer and a function `callPeel()` with the common boilerplate for each layer.

The code is improvable in many aspects and contains nearly no comments yet, because I was to lazy to add them, because I only wanted to solve the puzzle. Feel free to improve it and share the result.


## Help appreciated

I've solved the puzzle up to the final layer without any obvious error, but the final result seems to be wrong even when I consider what Tom said about the final result.

So, I would like to hear from you if you discover any bugs in the code, particularly if they lead to a more plausible result.


## Acknowledgements

First of all thanks [Tom](https://www.tomdalling.com) for this nice and challenging puzzle, which made me learn something new.

Thanks to [*iKieronJ*](https://www.reddit.com/user/iKieronJ/) on [Reddit](https://www.reddit.com) for his [hint](https://www.reddit.com/r/programming/comments/haqil8/toms_data_onion_a_programming_puzzle_in_a_text/fv8fjdy/) about using Python to solve layer 5.

