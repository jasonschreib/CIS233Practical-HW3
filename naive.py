from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import random

from collections import Counter

DEBUG = True
DEFAULT = 0

class Message:
    def __init__(self, value, sig):
        self.value = value
        self.sig = sig


#class for party
class Party:
    def __init__(self, is_leader, num, honest):
        self.is_leader = is_leader
        self.sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pk = self.sk.public_key()
        self.num = num
        self.msgs = []
        self.is_honest = honest
        self.output = 1

    def sign(self, v):
        msg = bytes((v, self.num))
        return Message(v, self.sk.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))

    def send(self, party, msg, PKI):
        if not self.is_honest:
            # TODO: Implement a dishonest send protocol
            #  if dishonest and random generator is .5 or above, then do nothing
            if random.random() >= 0.5:
                return
            # otherwise set message value to 0 if the party number is even
            elif party.num % 2 == 0:
                msg.val = 0
            # otherwise set message value to 1
            else:
                msg.val = 1
        if DEBUG: print("Sending", msg.value, "from", self.num, "to", party.num)
        # validates the sig, adds it to the list of messages if valid
        party.recieve(msg, PKI)

    def recieve(self, msg, PKI):
        _sig = msg.sig
        _msg = bytes((msg.value, 0))
        
        try:
            # Verify that the message was signed by the general
            PKI[0].verify(_sig, _msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except InvalidSignature:
            return

        self.msgs.append(msg)

    def relay(self, party, PKI):
        # TODO: Implement relay for honest party: If you recieved a message, forward it to the specified party
        if self.is_honest:
            # send the last message in the message array for this party
            # if the length of messages is nonzero
            if len(self.msgs) > 0:
                # send with last message in the msgs list
                self.send(party, self.msgs[-1], PKI)
        # TODO: Implement relay for dishonest party - dishonest party will send nothing
        else:
            return

    def decide(self):
        # TODO: implement decision step for both honest and dishonest parties
        # if self is honest
        if self.is_honest:  
            # instantiate a counter
            numOccurrences = Counter(list(message.value for message in self.msgs))
            # if the len of the counter list equals 1,
            if len(numOccurrences) == 1:
                #set the output to the first item in the list
                self.output = numOccurrences[0]
            #otherwise
            else:
                #set the output to the default
                self.output = DEFAULT
        # otherwise
        else:
            # just return with the original value set to 1
            return

def validity(general, v, parties):
    if general.is_honest:
        all_outputs = set([p.output for p in parties if p.is_honest])
        return len(all_outputs) == 1 and all_outputs.pop() == v
    else:
        return True

def agreement(parties):
    return len(set([p.output for p in parties if p.is_honest])) == 1


'''
    Naive Byzantine Agreement Protocol Implementation
    Takes a list of parties and a public key mapping
    (Check the tests for usage)
'''


def protocol(parties, PKI):
    
    #Round 1 
    v = 0

    leader = [p for p in parties if p.is_leader]
    assert(len(leader) == 1)
    G = leader[0]

    msg = G.sign(v)
    
    if DEBUG: print("ROUND 1")

    for party in parties:
        if not party.num == G.num:
            G.send(party, msg, PKI)


    if DEBUG:
        print()
        print("ROUND 2")

    #Round 2 
    for party in parties:
        for partyj in parties:
            if not party.num == partyj.num:
                party.relay(partyj, PKI)


    #Decision rule
    for party in parties:
        party.decide()
        
        
    if DEBUG: print("OUTPUTS", [p.output for p in parties])

    _valid = validity(G, v, parties[1:])
    _agreed = agreement(parties)

    return _valid and _agreed


