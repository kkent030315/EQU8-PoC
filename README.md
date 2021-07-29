<p align="center">
<img src="https://www.godeye.club/assets/images/post/3927692069032.png">
</p>

<p align="center">
<img src="https://img.shields.io/badge/platform-win--64-00a2ed?style=for-the-badge">
<img src="https://img.shields.io/github/license/kkent030315/anycall?style=for-the-badge">
</p>

# EQU8-PoC
A proof-of-concept to abuse EQU8 anti-cheat kernel driver

The below article covers full implementation of the equ8 kernel driver.
https://www.godeye.club/2021/07/28/001-abusing-equ8-anti-cheat.html

# Features

- `EQU8_IOCTL_ENABLE_PROTECT`: Abusing EQU8's object callback protection
- `EQU8_IOCTL_FETCH_DETECTION_TABLE`: Fetch detection table and erase
    - access-mask, `OB_PRE_OPERATION_INFORMATION->KernelHandle`, requestor-pid, target-pid
