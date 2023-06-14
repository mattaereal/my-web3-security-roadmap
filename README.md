# My personal roadmap (out of date)
My own tailored roadmap, to my web3 / smart contract auditor knowledge.

The primary purpose of this road map is to document the resources that piqued my interest throughout the studies of the security perspective and the underlying technologies of this ecosystem.

### Disclaimer
This is not in any way the ultimate roadmap, nor the best, neither a good one. It's just what I considered while I was studying my way through web3 security, particularly evm-based content. I'm in need to clarify this because there has been at least more than 20 "ultimate roadmaps++" since I, at least, started learning, and each one of them are clearly subjective, so you need to create your own roadmap according what you want to learn. Wat you need to do first is learn the minimum necessary to have an idea of what you want to learn following your needs or objectives.

⭐ → highlighted article

👌🏽 → personal liking

♦️ → mandatory to read / check out / save for later

# Table of contents

# Main road-map

1. **Introduction to Blockchain**
    - [ ]  [Blockchain fundamentals](https://www.youtube.com/watch?v=V0JdeRzVndI) (⭐) by Dan Boneh
    - [ ]  [Blockchain demo (interactive)](https://andersbrownworth.com/blockchain/) (♦️) — I always use this when I have to explain the basics!
2. **Introduction to Solidity**
    1. Quick start
        - [ ]  [Solidity walk-through](https://solidity-walkthrough.vercel.app/) — suuper quick glance at Solidity
        - [ ]  🧟 [CryptoZombies](https://cryptozombies.io/en/course/) — brief but entertaining
        - [ ]  [Solidity by example](https://solidity-by-example.org/) (⭐) — check video explanations!
    2. Ideal
        - [ ]  [HardHat](https://hardhat.org/tutorial/)'s tutorial (👌🏽) — first tooling experience
        - [ ]  [FreeCodeCamp 32 hours course](https://www.youtube.com/watch?v=gyMwXuJrbJQ) (⭐👌🏽) — totally recommended (uses Hardhat)
        - [ ]  [Tic Tac Token](https://book.tictactoken.co/) — select a kata, and start a short project on Foundry
    3. Additional
        - [ ]  🏃🏾‍♀️[SpeedrunEthereum](https://speedrunethereum.com/) (⭐)
        - [ ]  ‣ — suggestions [after scaffold-eth](https://twitter.com/austingriffith/status/1478760479275175940)
        - [ ]  🐰 [RabbitHole](https://rabbithole.gg/) — L2, DeFi, NFT, DAOs!
3. **Introduction to the EVM**
    1. Quick start
        - [ ]  [Take glimpse over Yul](https://docs.soliditylang.org/en/latest/yul.html) — the intermediary language
        - [ ]  [EVM Codes](https://www.evm.codes/) ♦️ — incredible tool and resource
        - [ ]  [EtherVM](https://www.ethervm.io/) ⭐ — read at least once
        - [ ]  https://github.com/fvictorio/evm-puzzles https://github.com/daltyboy11/more-evm-puzzles 👌🏽— play with these challenges
            - [ ]  [solving more-evm-puzzles diferrently](https://medium.com/@mattaereal/solving-more-evm-puzzles-differently-part-i-170f2516b88d) by matta. 👌🏽
    2. Strongly recommended
        - [ ]  🧩 [yet-another-evm-puzzle](https://github.com/mattaereal/yet-another-evm-puzzle/) by matta. ⭐ — puzzles with a realistic twist
        - [ ]  [Solving yet another EVM puzzle](https://www.notonlyowner.com/writeups/yet-another-evm-puzzle/) by tincho ⭐ — amazing write-up
    3. Further reading
        - [ ]  [Solidity data representation](https://ethdebug.github.io/solidity-data-representation/)
        - [ ]  [The EVM Handbook](https://www.notion.so/bb38e175cc404111a391907c4975426d) — large collection of sources
4. **Skim through / read a bit of / know that this exists and is important**
    - [ ]  [Latest Solidity documentation](https://buildmedia.readthedocs.org/media/pdf/solidity/develop/solidity.pdf) ♦️ — official readthedocs for Solidity
    - [ ]  [OpenZeppelin's contracts](https://docs.openzeppelin.com/contracts/4.x/) ⭐ — most reused Solidity code on the blockchain
    - [ ]  [What’s a computer hacker?](https://medium.com/@mattaereal/whats-a-computer-hacker-and-other-popular-questions-c147b9a50f58) *and other popular questions —* seeking motivation?
5. **Road-maps / general guides / classes / courses**
    1. Quick reading
        - [ ]  [A Journey Into Smart Contract Security](https://medium.com/@mattaereal/a-journey-into-smart-contract-security-3115ff480f28) (👌🏽) — short collection of articles I’ve written
        - [ ]  [How to become a smart contract auditor](https://cmichel.io/how-to-become-a-smart-contract-auditor/) (⭐👌🏽) by cmichelli
        - [ ]  [How to Develop Smart Contracts for Ethereum Blockchain](https://web3.career/learn-web3) by web3.career
        - [ ]  [Roadmap for Web3/Smart Contracts hacking 2022](https://sm4rty.medium.com/roadmap-for-web3-smart-contract-hacking-2022-229e4e1565f9) by **sm4rty**
    2. Will take a while
        - [ ]  [Working in Web3: The handbook](https://web3.smsunarto.com/) (⭐) by [**smsunarto**](http://twitter.com/smsunarto)
        - [ ]  https://github.com/fravoll/solidity-patterns (👌🏽) — Some known [Solidity patterns](https://fravoll.github.io/solidity-patterns/)
    3. Buckle up
        - [ ]  [Cryptocurrency Class 2022](https://cryptocurrencyclass.github.io/) by Patrick McCorry (Infura)
        - [ ]  [Useful solidity patterns](https://github.com/dragonfly-xyz/useful-solidity-patterns?utm_source=substack&utm_medium=email#readme) (👌🏽)
    4. Alternative
        - [ ]  [How to become an auditor & hunter](https://officercia.mirror.xyz/FvMKbibx7gDlufgZSkmYn77CI8HPBsVCeqUKmpXHr0k) by CIA Officer 👮🏻‍♂️
        - [ ]  ‣
6. **Security specific content**
    - [ ]  [Hack the blockchain](https://www.notion.so/b26aec3d920e414d8a354618d3e36eb4): Blockchain Security Guide. — very long, and similar to this list
    - Good practices and patterns
        - [Solidity security anti-patterns](https://blog.sigmaprime.io/solidity-security.html) — a great list
        - [DeFi security practices](https://www.certik.com/resources/blog/top-10-defi-security-best-practices)
        - https://github.com/crytic/building-secure-contracts
        - https://github.com/sigp/solidity-security-blog — list of known attack vectors and common anti-patterns
    - [ ]  Check out the [ultimate checklist](https://betterprogramming.pub/the-ultimate-100-point-checklist-before-sending-your-smart-contract-for-audit-af9a5b5d95d0)
    - [ ]  Understand [SWC Registry](https://swcregistry.io/)
    - Check out the following repositories
        - ‣ — Smart Contract Security Verification Standard
        - https://github.com/Rivaill/CryptoVulhub — attack events or vulnerabilities
        - more repos at the end
    - [theauditorbook.com](https://theauditorbook.com/) — a book about high to mid vulns from Codearena & Sherlock
7. **Play a bit with**
    - [ ]  Real-scenarios alike
        - [ ]  👾 [Damn Vulnerable Defi](https://www.damnvulnerabledefi.xyz/) (♦️) by tinchoabbate
        - [ ]  https://github.com/eugenioclrc/DeFi-Security-Summit-Stanford — short and interesting
            - [ ]  Follow the solutions with [my walk-through](https://medium.com/@mattaereal/a-maze-x-ctf-walkthrough-part-0-d73338e6809) (⭐) — I really did put effort on this serie
    - [ ]  Some more
        - [ ]  🧑🏽‍🚀 [Ethernaut](https://ethernaut.openzeppelin.com/) (⭐)
            - [ ]  [Solutions](https://cmichel.io/ethernaut-solutions/) by cmichel
        - [ ]  ✊🏽 [Capture the ether](https://capturetheether.com/) by smarx
        - [ ]  [Ethereum Hacker](https://ethereumhacker.com/)
    - [ ]  Find more under CTFs category below
8. **Create content on your own**
    1. Quick start
        - [ ]  Post on forum / social network about something you’ve found useful
        - [ ]  Post your solution for a challenge
    2. A step further
        - [ ]  Create a challenge and share it!
        - [ ]  Create a post sharing something you’ve found useful
9. **Bounties**
    - Blockchain & Web3
        - 👽 [Immunefi](https://immunefi.com) — web3 bug bounty platform
        - ⌛ [Code4rena](https://code4rena.com/) — crowdsourced web3 bug bounty platform
        - ⭕ [HackenProof](https://hackenproof.com/) — web3 bug bounty platform
        - 🪙 [GitCoin bounties](https://gitcoin.co/bounties/funder) — bounty collaboration
    - General purpose platforms
        - 1️⃣ [HackerOne](https://hackerone.com/users/sign_in)
        - 🐞 [Bugcrowd](https://bugcrowd.com/programs)
10. **Projecting jobs? Go back to 2. as well**
    - [ ]  Differentiate where your skills excel and look for project's affinity
    - [ ]  Involve / engage more in communities / projects that you like
        - [ ]  Recommended discords
            - [ ]  [WebtrES](https://discord.gg/C6FZHydv) (Spanish)
            - [ ]  [ManijasDev](https://discord.gg/umBsGP3d) (Spanish)
            - [ ]  [EthSecurity](https://discord.gg/22nBtRF2) (English)
    - [ ]  [Look for apprenticeships / fellowships / internships](https://www.google.com/search?q=%28%22apprenticeship%22+OR+%22internship%22+OR+%22fellowship%22%29+AND+%28web3+OR+solidity%29&biw=1422&bih=703&sxsrf=ALiCzsZmINcb2gzrBxC2FNBJ3QbtcefeXQ%3A1668437610892&ei=alZyY-6INvve1sQPsI2w4Aw&ved=0ahUKEwju5YG59q37AhV7r5UCHbAGDMwQ4dUDCA8&uact=5&oq=%28%22apprenticeship%22+OR+%22internship%22+OR+%22fellowship%22%29+AND+%28web3+OR+solidity%29&gs_lcp=Cgxnd3Mtd2l6LXNlcnAQAzoHCCMQsAMQJzoKCAAQRxDWBBCwAzoECCMQJzoFCAAQogQ6BwgjELACECc6CgghEMMEEAoQoAFKBAhBGABKBAhGGABQ4AhYqegBYKzrAWgGcAF4AYABuwGIAcAhkgEFMzguMTCYAQCgAQHIAQnAAQE&sclient=gws-wiz-serp)
    - [ ]  Or even your first job too! — thanks @tomasfrancisco for contributing with links
        - [web3.career](https://web3.career)
        - [web3internships.com](https://www.web3internships.com/)
        - [www.alljobsinweb3.com](https://www.alljobsinweb3.com/)
        - [cryptocurrencyjobs.co](https://cryptocurrencyjobs.co/)
        - [crypto.jobs](https://crypto.jobs/)
        - [defi.jobs](https://defi.jobs/)
        - [jobs.buildspace.so](https://jobs.buildspace.so/)
        - [useweb3.xyz](https://useweb3.xyz/)
        - [web-3.pallet.com](https://web-3.pallet.com/)
        - [pompcryptojobs.com](https://pompcryptojobs.com/)
        - [remote3.co](https://remote3.co)
        - [web3 job spreadsheet](https://docs.google.com/spreadsheets/d/1VDi6ZdhLIWjg_s2s2JDF2E6RehMBzrQ0OqIoTQ5wQN0/htmlview) - updated daily
            - [Looking for a job?](https://airtable.com/shrqCnycII5vjEmeJ)
            - [Submit your job](https://airtable.com/shr4rDjmfku3bzueC)!

# Tools

### Utilities

- ‣ — replace etherscan.io/[tx] with etherscan.deth.net/[tx] and see what happens ;)
- 🔎 [4byte directory](https://www.4byte.directory/) | [sig.eth](https://sig.eth.samczsun.com/) — a database with known function selectors
- 🔪 [dETH tools](https://tools.deth.net/eth-unit-conversion) — encoding, decoding, function selectors, abi and more
- [Cyberchef](https://gchq.github.io/CyberChef/) ♦️ — general purpose tool, excellent for CTFs and web2 audits
- https://github.com/apoorvlathey/impersonator — impersonate any account with [impersonator.xyz](http://impersonator.xyz)
- https://github.com/samczsun/abi-guesser — Abi Guesser by samczsun

### Toolkits

- ‣ — EVM lab utilities
- https://github.com/Jon-Becker/heimdall-rs 🔥 — advanced EVM toolkit

### **Tracers**

- [ethTX](https://ethtx.info/mainnet/0x631d206d49b930029197e5e57bbbb9a4da2eb00993560c77104cd9f4ae2d1a98/) — ethereum transaction decoder
- [Phalcon by blocksec](https://phalcon.blocksec.com/) — transaction Explorer (works on several networks)
- [tx.eth.samczsun.com/](https://tx.eth.samczsun.com/) — ethereum transaction viewe by sam
- [Breadcrumbs.app](http://Breadcrumbs.app) — open blockchain analytics platform
- [Event & Function signature Sleuthing](https://dune.com/agaperste/event-and-function-signature-sleuthing?utm_source=substack&utm_medium=email) — investigate events and functions further 🕵️
- [NansenAI](http://nansen.ai) — paid subscription, blockchain analytics platform
- [SocketScan](https://socketscan.io/) — track transactions across bridges (all chains)
- [A bigger list with more block explorers!](https://www.notion.so/8dcaed059c844e3b8f9b67b8eb90174a)

### Disassembly

- https://github.com/crytic/ethersplay — EVM plugin for Binary Ninja

### Decompilers

- https://github.com/eveem-org/panoramix — another decompiler
- [ethervm.io](https://ethervm.io/decompile) — online decompiler
- [ABI for unverified contracts](https://abi.w1nt3r.xyz/)
- https://github.com/Jon-Becker/heimdall-rs — also includes a decompiler

### Static analysis / Symbolic exec / Fuzzing

- [Slither](https://github.com/crytic/slither) - Static analysis from Trail of Bits.
- [Echidna](https://github.com/crytic/echidna) - Fuzzing from Trail of Bits.
- [Manticore](https://github.com/trailofbits/manticore) - Symbolic execution tool from Trail of Bits.
- [MythX](https://mythx.io/) - Paid service for smart contract security from Consensys.
- [Mythrill](https://github.com/ConsenSys/mythril) - MythX free edition.

### VSCode extensions

- `tintinweb.vscode-ethover` — ethereum account address hover info and actions
- `esbenp.prettier-vscode` — prettify all the things!
- `NomicFoundation.hardhat-solidity` — Solidity and Hardhat support
- `tintinweb.vscode-solidity-flattener` — flatten your projects
- `tintinweb.vscode-solidity-language` — language support, highlighting, and themes
- `tintinweb.solidity-visual-auditor` — source exploration and visual linting, among others
- `tintinweb.vscode-decompiler` —  decompile the $h*! out of things

### Bundles

- [ETH Security Toolbox](https://github.com/trailofbits/eth-security-toolbox) - Docker containers with Trail of Bits security tools.
- [Consensys Security Tools](https://consensys.net/diligence/tools/) - A list of Consensys tools.

### Misc

- https://github.com/nccgroup/web3-decoder — BurpSuite extension for web3

### Develpment tools

- [Eth Build](http://eth.build) — An Educational Sandbox For Web3
- [Ethereum developer tool-list](https://github.com/ConsenSys/ethereum-developer-tools-list) by Consensys — +100 tools
- [TheGraph](http://thegraph.com) — indexing protocol for querying networks like Ethereum and IPFS
- [Filecoin](https://filecoin.io/) — a descentralized storage network
- [Moralis](http://moralis.io) — web3 development platform, build dApps
- [Alchemy](http://alchemy.com) — build and scale you dApps
- [Dune](https://dune.com/home) — explore, create and share crypto data
- [CREATE3 | Deploy contract with same address to al blockchains](https://github.com/ZeframLou/create3-factory?utm_source=substack&utm_medium=email#readme)

## CTFs / Challenges

- [Cipher Shastra CTF-like](https://ciphershastra.com/index.html) challenges
- 🏁 [Paradigm CTF 2021](https://github.com/paradigm-operations/paradigm-ctf-2021) — [solutions](https://cmichel.io/paradigm-ctf-2021-solutions/) by cmichel
- 🏁 [Paradigm CTF 2022](https://ctf.paradigm.xyz/) ([0xMonaco](https://0xmonaco.ctf.paradigm.xyz/howtoplay))
- 📃 [Ethernaut DAO CTF](https://stermi.xyz/blog/ethernautdao-ctf-ethernautdao-token-solution?r=15ekxo&utm_source=substack&utm_medium=email) — [Challenges & WriteUps](https://github.com/beskay/solidity-challenges)
- [White Noise](https://ctf.whitenoise.rs/) CTF
- [OpenZeppelin's Ethernaut Challenges](https://www.youtube.com/playlist?list=PLBy3Qkuapv_7R1ZI_Cs2NOFn7ZTaNWY6G) 📺
- [Damn Vulnerable DeFi solutions](https://www.youtube.com/watch?v=A5s9aez43Co&list=PLO5VPQH6OWdXKPThrch6U0imGdD3pHLXi) 📺 by SmartContractProgrammer
- [CryptoCTF](https://cr.yp.toc.tf/)
- [EtherHack](https://etherhack.positive.com/) at Positive
- https://github.com/blockthreat/blocksec-ctfs
- [NodeGuardians](https://nodeguardians.io/dev-hub/quests/storage-layout)

# Newsletters & feeds

- **[Weekly in Ethereum](https://weekinethereum.substack.com/)**
- [**BlockThreat Newsletter**](https://newsletter.blockthreat.io/)
- [**Rekt News**](https://feed.rekt.news/)
- [**Web3 Is Doing Just Great**](https://web3isgoinggreat.com/)

## People (WIP)

**Security related**

[@tinchoabbate](http://twitter.com/tinchoabbate), [@samcszun](https://twitter.com/samczsun), [@0xZachxBT](https://twitter.com/zachxbt), [@officer_cia](https://twitter.com/officer_cia), and me [@mattaereal](http://twitter.com/mattaereal).

**General purpose**

[@smsunarto](https://twitter.com/smsunarto/status/1453177837003833349), [@austingriffith](https://twitter.com/austingriffith), [@0xcygaar](https://twitter.com/0xCygaar), [@programmersmart](https://twitter.com/ProgrammerSmart), [@web3isgreat](https://twitter.com/web3isgreat).

**Fun / Parody**

[@jomaoppa](https://twitter.com/jomaoppa)

# Other sources of information

- [Use Web3](https://www.useweb3.xyz/tutorials) website: challenges, tutorials, grants, and more!
- [The story behind the alternative genesis block](https://serhack.me/articles/story-behind-alternative-genesis-block-bitcoin/?utm_source=substack&utm_medium=email)
- [Upgrading Ethereum](https://eth2book.info/latest) “The ETH2 book”— A technical handbook on Ethereum's
- [Beginner's Guide to Bitcoin Mixing](https://bitblender.io/guide.html#INTRODUCTION)
- [A (Relatively Easy To Understand) Primer on Elliptic Curve Cryptography](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/)
- [Devcon 6 Security track](https://www.youtube.com/playlist?list=PLaM7G4Llrb7zeG1z6u-cRFfphiECL-_FD)
- [Ethereum smart contracts security recommendations and best practices](https://github.com/guylando/KnowledgeLists/blob/master/EthereumSmartContracts.md)
- Relevant Security GitHub repositories
    - ‣ — list of security practices for DeFi protocols.
    - https://github.com/blocksecteam/defi_poc — PoC for DeFi Vulnerabilities
    - https://github.com/YAcademy-Residents/CommonWeb3SecurityIssues — common security findings in smart contracts
- [Tech & VC: The Foundation](https://www.notion.so/Tech-VC-The-Foundation-c6ad4b799aa4490dbe05b3d49c288aa3)
- https://github.com/coinspect/learn-evm-attacks — Learn & Contribute on previously exploited vulnerabilities across several EVM projects.
- https://github.com/0xNazgul/Blockchain-Security-Audit-List — A list of notable Blockchain Security audit companies.
- https://github.com/OffcierCia/Crypto-OpSec-SelfGuard-RoadMap — *DeFi, Blockchain and crypto-related OpSec researches and data terminals.*

# Further reading

### DeFi

- DeFi security small write-up series [part I](https://halborn.com/defi-security-part-1-data-security-vulnerabilities), [part II](https://halborn.com/defi-security-part-2-consensus-vulnerabilities/?utm_source=substack&utm_medium=email), [part III](https://halborn.com/defi-security-part-3-smart-contract-vulnerabilities/?utm_source=substack&utm_medium=email) by Halbron
- [Introduction to markets by UniswapBooksV3](https://uniswapv3book.com/docs/introduction/introduction-to-markets/)
- [The Uniswap Standard, from Zero to Mastery](https://mirror.xyz/haruxe.eth/q-2jXIvcXI4cPDgmQLac1L_iQ6zXgbmCtIhgCHnabc8)

### Finance / economics

- Khan Academy - [Economics / Finance domain, core principles](https://www.khanacademy.org/economics-finance-domain/core-finance/derivative-securities/put-call-options)
- [Vulnerable spots of lending protocols](https://mixbytes.io/blog/vulnerable-spots-of-lending-protocols#submenu:liquid-staking)

### Tokens

- ‣
- [Token interaction checklist](https://consensys.net/diligence/blog/2020/11/token-interaction-checklist/)
- [Token integration](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/token_integration.md)
- [Weird tokens](https://github.com/d-xo/weird-erc20)

### Tokenomics

Link compilation credits to CIA Officer

- [cadcad.org](http://cadcad.org/) — An open-source Python package that assists in the processes of designing, testing and validating complex systems through simulation.
- [tecommons.org](http://tecommons.org/) — **Sustainable & Ethical Design for Token Ecosystems**
- [machinations.io](http://machinations.io/) — ****Predict Game Economies & Systems****
- https://github.com/jpantunes/awesome-cryptoeconomics #1 — ‣ #2
- https://github.com/melonattacker/utility-token-price-simulator — simulates general token price when setting parameters.
- https://github.com/tokenspice/tokenspice — EVM agent-based token simulator

### NFTs

- [Trending NFT Collections by Sales](https://icy.tools/)
- [Real-time NFT insights and high-fidelity data](https://uniq.cx/)
- [Your go-to destination for Web3 Social Intelligence](https://www.nftinspect.xyz/)
- [The #1 source for NFT rarity](https://raritysniper.com/)

### MEV

- [The 0 to 1 guide on MEV](https://calblockchain.mirror.xyz/c56CHOu-Wow_50qPp2Wlg0rhUvdz1HLbGSUWlB_KX9o?utm_source=substack&utm_medium=email)

### Optimization (WIP)

- [Optimizers guide to Solidity](https://medium.com/@omniscia.io/the-optimizers-guide-to-solidity-pt-1-access-of-mapping-entries-9f852aa5e38)
- Up to 4 functions are ordered by their function selector when calling. After 4 functions, it’s done by binary search.
- Using custom errors consumes less gas than other options.
- `extcodecopy` `codecopy` are cheaper than `ssload` `sstore`.
- `(bool success, bytes memory returnData) = target.call()` automatically copies the return data to memory even if you omit the returnData variable. If a relayer executes transactions with such calls it can lead to a gas-griefing attack. The proper way to handle this is to do a low-level Yul "call" instead, with "out" and "outsize" argument values are zero. It looks like `success := call(gas, target, value, add(calldata, 0x20), mload(calldata), 0, 0)` where the last 2 args are "out" & "outsize" and are both 0 — by pashov
- In cases where you don’t need to use 32 bytes variables, in order to save gas, you should pack multiple variables inside the same slot using bit manipulation. Caveats: losing type safety.

### Zero Knowledge proofs

[ZK Class: Introduction to ZKP](https://www.youtube.com/watch?v=-2qHqfqPeR8&t=1s)

### Take a test!

- [Test yourself by rareskills](https://www.rareskills.io/test-yourself)

### Secureum

https://github.com/x676f64/secureum-mind_map

👢🏕️ [bootcamp: when, how & where](https://gist.github.com/patrickd-/bb9d22956147d91fc458b23426f16ab7)
