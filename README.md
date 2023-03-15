# Protocols for Byzantine Agreement

In this assignment, you will implement three protocols for byzantine assignment. 
You can use this link as reference: https://decentralizedthoughts.github.io/2019-12-22-dolev-strong/

## Set-up

1. Clone this repo and open in the editor of your choice.
2. Install the `cryptography` python package which we will be using, in your terminal

```
pip install cryptography
```

Note: make sure you install the package via terminal using the same python installation, more on [this](https://edstem.org/us/courses/35448/discussion/2440264). 
## Part 1: Two Round Byzantine Agreement with Digital Signatures `naive.py`

First, you will implement a protocol with digital signatures. 

Study the `protocol` function. It functions as follows:

```
Round 1: Leader (party 1) sends message <v, sign(v,1)> to all parties
Round 2: If party i receives <v, sign(v,1)> from leader,
            then add v to V_i and send <v, sign(v,1)> to all
End of round 2: 
         If party i receives <v, sign(v,1)> from anyone
            then add v to V_i
Decision rule:
         If the set V_i contains only a single value v,
            then output v
         Otherwise output a default value bot
```


Let's go through the code we've provided to understand how it corresponds to the above algorithm.

First, there is a variable for turning on `DEBUG` print statements. This will be useful in debugging your code and answering the required questions.
Then, we define a global `DEFAULT` value for the decision step.

Next, we define a `Message` class. In this Byzantine Agreement protocol, the message will have a value and a single signature. Note that in Dolev-Strong (the next part of this assignment), a message can contain multiple signatures.
We also define a `Party` class. Each party has a private and public key (`sk` and `pk`). The secret key will be used to sign messages and the public key will be used for other parties to verify those messages.
A `Party` also keeps track of its party number, if it is the leader, and if it is honest. A Party i also keeps a set of valid messages: `V_i`. 
Lastly, it has a field `output` which is set during the decision step. 


The `Party` class also has a number of functions you will implement. First let's look at the `protocol` function.
`protocol` takes a list of party objects: `parties` as well as a Public Key Infrastructure (PKI) from which we can access party number to public key pairs.

In the first round, the leader signs the message and sends it to every other party.
The `sign` function takes a bit v, and returns a Message object. `sign` uses the python Cryptography library to create a digital signature with the parties secret key.
The `send` function takes a receiver party, a Message object to send, and the PKI. 
Now let's take a look at the `Party send` function.  We implement this using a `Party receive` function.
`receive` validates the signature using the general's public key and adds it to the list of messages if it is valid.

In the second round, each honest party relay's its message to all other parties.

Lastly, there is a decision round. 


Your task is to fill in the `TODO`s:
1. `send`: Here, honest behavior is provided. Implement behavior for a dishonest party. Think adversarily about all of the ways a faulty party can act (any behavior is ok! The algorithms we present say nothing about how a malicious party may act).
2. `relay`: An honest party will forward the last message it has received. Implement functionality for both honest and dishonest parties. Hint: use `send` as a helper function.
3. `decide`: According to the above algorithm, an honest party will output a decision bit only if all messages in their `msg` list contain the same bit. Otherwise, it will output default. Implement this as well as  decision functionality for a dishonest party. Remember, any behavior is allowed!


Now lets check out the tests. When the general is dishonest, it should not satisfy validity and agreement. 
When all parties are honest, both properties should be satisfied.

Once your tests pass, fill out the following table with the values each party has at the end of the specified round as well as the decision value:
If you set the `DEBUG` variable to `True` it will the print the messages that were sent.


|    | P0 (General) | P1 | P2 | P3 | P4 |
|----|--------------|----|----|----|----|
| R0 |              |    |    |    |    |
| R1 |              |    |    |    |    |
| D  |              |    |    |    |    |



For example, given the sequence:
(NOTE THIS IS A FAKE SEQUENCE AND DOES NOT FOLLOW THE PROTOCOL WHICH YOU WILL IMPLEMENT)
ROUND 1
Sending 0 from 0 to 3
Sending 1 from 0 to 4

ROUND 2
Sending 1 from 0 to 1
Sending 1 from 0 to 2
Sending 0 from 0 to 3
Sending 0 from 0 to 4
OUTPUTS [0, 1, 1, 0, 1]

The table should look as follows:

|    | P0 (General) | P1 | P2 | P3  | P4  |
|----|--------------|----|----|-----|-----|
| R0 |              |    |    | 0   | 0   |
| R1 |              | 1  | 1  | 0,0 | 0,0 |
| D  | 0            | 1  | 1  | 0   | 0   |


Explain in words the situation in which validity and agreement do not hold.

The situation in which validity and agreement do not hold is when the general is dishonest.

## Part 2: Dolev-Strong `ds.py`
Now that we've motivated the need for a stronger protocol to satisfy validity and agreement, you will implement the Dolev-Strong protocol.

```
// Leader (party 1) with input v

Round 1: send <v, sign(v,1)> to all parties.

Party i

does the following:

// Party i in round j

For a message m arriving at the beginning of round j:
  if party i has sent less than two messages; and
    if m is a valid (j-1)-signature chain on $v$, then
        add v to V
        send <m, sign(m,i)> to all parties

// Party i decision rule

Decision at the end of round t+1:
  Let V be the set of values for party i received a valid signature chain
  If |V|=0 or |V|>1, then decide default value bot
  Otherwise decide v, where V={v}
```

This differs from the previous algorithm in two major ways:   
1. Number of rounds
2. Each message has a signature chain rather than a single signature by the general. This indicates the party which is sending it. It also indicates which round it was received by the length of the signature chain.


The code we've provided for `ds.py` differs from the naive implementation to reflect this.
First, we've added a `Signature` class for ease. It includes the digital signature as well as the party which signed. 
Next, the message object holds a list of signatures rather than a single signature. It also includes an `add_sig` function. 

The `Party` `send` and `receive` functions now take a `round_num` argument for validating that the signature chain is of the correct length.

The validation now requires looping over each signature as well as checking the length of the chain is equal to the current round number.


Your task is to fill in the `TODO`s:
1. `send`: Here, honest behavior is provided. Implement behavior for a dishonest party. Think adversarily about all of the ways a faulty party can act (any behavior is ok! The algorithms we present say nothing about how a malicious party may act).
2. `relay`: An honest party will **add its signature** and forward the last message it has received. Implement functionality for both honest and dishonest parties. Hint: use `send` as a helper function.
3. `decide`: According to the above algorithm, an honest party will output a decision bit only if all messages in their `msg` list contain the same bit. Otherwise, it will output default. Implement this as well as  decision functionality for a dishonest party. Remember, any behavior is allowed!


## What to submit

Submit your code as well as the table you created in Part 1 to the gradescope.
