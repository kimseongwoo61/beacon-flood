# Beacon Flooding Attack!!!

기일: 2023.01.16

### 1. 개요

- 해당 코드는 Monitor mode의 무선랜 인터페이스에서 802.11 비콘 프레임 공격기능을 탑재하였으며, 파이썬 기반으로 작성되어 있습니다.
- 의존 모듈 : sys, socket, struct, random, binascii
- 사용법
    
    입력되는 무선랜 인터페이스가 반드시 Monitor mode여야 정상적으로 Beacon flooding 공격이 가능합니다.
    
    ```python
    sudo python beacon-flood.py <interface> <ssid-list-file>
    ```
    

### 2. 참고사항

- 비콘 플러딩 공격을 수행할 시 MAC 주소는 임의로 생성됩니다.
- 공격의 성공률을 높히기 위해 신호세기(안테나 시그널)를 임의적으로 강한세기로 인식하도록 하였습니다.
