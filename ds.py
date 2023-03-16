from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import random
from collections import Counter

DEBUG = False
DEFAULT = 0

class Signature:
    def __init__(self, num, sig):
        self.party_num = num
        self.sig = sig

class Message:
    def __init__(self, value, sigs, r):
        self.value = value
        self.sigs = sigs
        self.round = r

    def add_sig(self, sig):
        self.sigs.append(sig)

    def __str__(self):
        return str(self.value) + ", " + ",".join(["P" + str(sig.party_num) for sig in self.sigs])

#class for party
class Party:
    def __init__(self, is_leader, num, honest):
        self.is_leader = is_leader
        self.sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pk = self.sk.public_key()
        self.num = num
        self.msgs = []
        self.is_honest = honest
        self.output = None

    def sign(self, v):
        msg = bytes((v, self.num))
        sig = self.sk.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return Signature(self.num, sig)

    def send(self, party, msg, PKI, round_num):
        should_send = True
        if not self.is_honest:
            # if the random value generated is greater than 0.5
            if random.random() >= 0.5:
                # set message value as 0
                msg.val = 0
            # else if the party number is even
            elif party.num % 2 == 0:
                # set message value as 1
                msg.val = 1
            # otherwise
            else:
                return
        if should_send:
            if DEBUG: print("Sending", msg, "from", self.num, "to", party.num)

        party.recieve(msg, PKI, round_num)

    def recieve(self, msg, PKI, round_num):

        if round_num > 1 and not len(msg.sigs) == round_num:
            if DEBUG:
                print("Rejecting - wrong length of signature chain")
                print()
            return

        #verify all of the signatures
        for sig in msg.sigs:
            _msg = bytes((msg.value, sig.party_num))
            try:
                PKI[sig.party_num].verify(sig.sig, _msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            except InvalidSignature:
                if DEBUG:
                    print(sig)
                    print(sig.party_num)
                    print("Rejecting - forged signature")
                    print()

                return

        self.msgs.append(msg)

    def relay(self, party, PKI, round_num):
        #If you recieved a message in the previous round, add your signature forward it to the specified party
        last_round_msgs = [m for m in self.msgs if m.round == round_num-1]

        # relay for honest party: If received a message in prev round, forward it to specified party
        # if the party is honest
        if self.is_honest:
            # if the list of messages is nonzero
            if len(last_round_msgs) > 0:
                # iterate over messages
                for message in last_round_msgs:
                    # add signature to each messages
                    message.add_sig(self.sign(message.value))
                    # send the message
                    self.send(party, message, PKI, round_num)
            # otherwise, if no messages
            else:
                return
        # otherwise - dishonest
        else:
            return

    def decide(self):
        #TODO: implement decision step for both honest and dishonest parties
        if self.is_honest:
            # if num messages greater than 0
            if len(self.msgs) > 0:
                # set var for the first val in the array of keys
                OccurrencesFirstVal = self.msgs[0].value
                # set count var
                count = 0
                # iterate over the messages
                for m in self.msgs:
                    # if the val of curr message = first occurred val in array
                    if m.value == OccurrencesFirstVal:
                        # increment the count
                        count += 1
                # if count equals the length of the msgs
                if count == len(self.msgs):
                    # output the value
                    self.output = OccurrencesFirstVal
                else:
                    self.output = DEFAULT
            # otherwise
            else:
                # set the output to the default
                self.output = DEFAULT
        else:  # dishonest parties
            if random.random() <= 0.5:
                self.output = 1
            else:
                self.output = DEFAULT

def validity(general, v, parties):
    if general.is_honest:
        all_outputs = set([p.output for p in parties if p.is_honest])
        return len(all_outputs) == 1 and all_outputs.pop() == v
    else:
        return True

def agreement(parties):
    return len(set([p.output for p in parties if p.is_honest])) == 1

def protocol(parties, PKI, num_rounds):
    #Dolev-strong protocol implementation
    
    #Round 1 
    v = 0

    leader = [p for p in parties if p.is_leader]
    assert(len(leader) == 1)
    G = leader[0]

    msg = Message(v, [G.sign(v)], 1)
    
    if DEBUG: print("ROUND 1")

    round_num = 1
    for party in parties:
        if not party.num == G.num:
            G.send(party, msg, PKI, round_num)
    

    #Round 2 
    for r in range(2, num_rounds+1):

        round_num += 1

        if DEBUG:
            print()
            print("ROUND " + str(round_num))


        for party in parties:
            #If you recieved a message, forward it to everyone else
            for partyj in parties:
                if not party.num == partyj.num:
                    party.relay(partyj, PKI, round_num)


    #Decision rule
    for party in parties:
        party.decide()

        
    if DEBUG: print("OUTPUTS", [p.output for p in parties])

    _valid = validity(G, v, parties[1:])
    _agreed = agreement(parties)

    return _valid and _agreed

