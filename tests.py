from naive import Party
from naive import protocol 
from ds import Party as DsParty
from ds import protocol as ds_protocol
from tqdm import tqdm

def test_naive_faulty_general():
    faulty = False
    #TODO: change this back to 1000
    for i in tqdm(range(0, 10)):
        #create parties
        G = Party(True, 0, False) 
        p1 = Party(False, 1, True)
        p2 = Party(False, 2, True)
        p3 = Party(False, 3, True)
        p4 = Party(False, 4, True) 
        #.....

        parties = [G, p1, p2, p3, p4]

        PKI = {}
        for party in parties:
            PKI[party.num] = party.pk

        if not protocol(parties, PKI): 
            faulty = True
            break

    assert(faulty)


def test_naive_honest_general():
    faulty = False
    # TODO: change this back to 1000
    for i in tqdm(range(0, 10)):
        #create parties
        G = Party(True, 0, True) 
        p1 = Party(False, 1, True)
        p2 = Party(False, 2, True)
        p3 = Party(False, 3, True)
        p4 = Party(False, 4, True) 
        #.....

        parties = [G, p1, p2, p3, p4]
        
        PKI = {}
        for party in parties:
            PKI[party.num] = party.pk

        if not protocol(parties, PKI): 
            faulty = True
            print("NO AGREEMENT AND VALIDITY")
            break

    assert(not faulty)


def test_ds_faulty_general():
    faulty = False
    # TODO: change this back to 1000
    for i in tqdm(range(0, 10)):
        #create parties
        G = DsParty(True, 0, False) 
        p1 = DsParty(False, 1, True)
        p2 = DsParty(False, 2, True)
        p3 = DsParty(False, 3, True)
        #p4 = Party(False, 4, True) 
        #.....

        parties = [G, p1, p2, p3]#, p4]

        PKI = {}
        for party in parties:
            PKI[party.num] = party.pk

        if not ds_protocol(parties, PKI, 3): 
            faulty = True
            print("NO AGREEMENT AND VALIDITY")
            break

    assert(not faulty)

def test_ds_honest_general():
    faulty = False
    # TODO: change this back to 1000
    for i in tqdm(range(0, 10)):
        #create parties
        G = DsParty(True, 0, True) 
        p1 = DsParty(False, 1, True)
        p2 = DsParty(False, 2, True)
        p3 = DsParty(False, 3, True)
        p4 = DsParty(False, 4, True) 
        #.....

        parties = [G, p1, p2, p3, p4]
        
        PKI = {}
        for party in parties:
            PKI[party.num] = party.pk

        if not ds_protocol(parties, PKI, 3): 
            faulty = True
            print("NO AGREEMENT AND VALIDITY")
            break

    assert(not faulty)


print("TESTING")
print("====="*15)

try:
    test_naive_faulty_general()
    print("PART 1: TEST 1 PASSED")
except AssertionError as e:
    print("PART 1: TEST 1 FAILED")
    print("Validity and agreement should not hold when the general is dishonest")
    print()



try:
    test_naive_honest_general()
    print("PART 1: TEST 2 PASSED")
except AssertionError as e:
    print("PART 1: TEST 2 FAILED")
    print("Validity and agreement should hold when all parties are honest")
    print()


# try:
#     test_ds_faulty_general()
#     print("PART 2: TEST 2 PASSED")
# except AssertionError as e:
#     print("PART 2: TEST 1 FAILED")
#     print("Validity and agreement should not hold when the general is dishonest")
#     print()
#
#
# try:
#     test_ds_honest_general()
#     print("PART 2: TEST 2 PASSED")
# except:
#     print("PART 2: TEST 2 FAILED")
#     print("Validity and agreement should hold when all parties are honest")



