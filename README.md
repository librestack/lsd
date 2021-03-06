# LSD - The Librestack Daemon

<a href="https://scan.coverity.com/projects/librestack-lsd">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/21544/badge.svg"/>
</a>

<a href="https://opensource.org"><img height="150" align="right" src="https://opensource.org/files/OSIApprovedCropped.png" alt="Open Source Initiative Approved License logo"></a>

LSD is a complete 2.0 rewrite of GLADD to make it more modular and efficient.

LSD is a (pre)forking network daemon, which uses modules to handle requests.  It
aims to be small, simple, fast and secure.  External dependencies are kept to a
minimum.  By using a modular approach, code-paths are kept short, the attack
surface small, and yet it is flexible and extensible.

The rewrite is a work in progress, and GLADD has a bunch of features that are
not yet available in LSD.

LSD was created to work with and be the basis for various other Librestack /
Librecast projects.

## Modules

- http.so - simple https 1.1 webserver module with websockets support


## Questions, Bug reports, Feature Requests

New issues can be raised at:

https://github.com/librestack/lsd/issues

It's okay to raise an issue to ask a question.  You can also email or ask on
IRC.

<hr />

### IRC channel

`#librecast` on freenode.net

If you have a question, please be patient. An answer might take a few hours
depending on time zones and whether anyone on the team is available at that
moment. 

<hr />

<p class="bigbreak">
This project was funded through the <a href="https://nlnet.nl/discovery"> NGI0 Discovery </a> Fund, a fund established by NLnet with financial support from the European
Commission's <a href="https://ngi.eu">Next Generation Internet</a> programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825322. *Applications are still open, you can <a href="https://nlnet.nl/propose">apply today</a>*
</p>

<p>
  <a href="https://nlnet.nl/project/LibrecastLive/">
      <img width="250" src="https://nlnet.nl/logo/banner.png" alt="Logo NLnet: abstract logo of four people seen from above" class="logocenter" />
  </a>
  <a href="https://ngi.eu/">
      <img width="250" align="right" src="https://nlnet.nl/image/logos/NGI0_tag.png" alt="Logo NGI Zero: letterlogo shaped like a tag" class="logocenter" />
  </a>
</p>

