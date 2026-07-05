# pcap-programming

## 프로젝트 개요

C 언어와 `libpcap`을 사용하여 TCP 패킷을 캡처하고 분석하는 프로그램이다.

캡처한 패킷에서 Ethernet Header, IP Header, TCP Header, TCP Payload 정보를 출력한다. HTTP 트래픽의 경우 TCP Payload 영역에서 HTTP Message를 확인할 수 있다.

## 파일 구성

`tcp_packet_analyzer.c`  
TCP 패킷을 캡처하고 Header 정보와 Payload를 출력하는 메인 소스 코드

`myheader.h`  
Ethernet, IP, TCP Header 구조체가 정의된 헤더 파일

## 실습 환경

- 운영체제: WSL Ubuntu
- 사용 언어: C
- 컴파일러: `gcc`
- 사용 라이브러리: `libpcap`
- 캡처 인터페이스: `eth0`

## 설치

Ubuntu 환경에서 `libpcap` 개발 패키지가 필요하다.

```bash
sudo apt install libpcap-dev
```

## 컴파일 방법

```bash
gcc tcp_packet_analyzer.c -o tcp_packet_analyzer -lpcap
```

## 실행 방법

패킷 캡처에는 관리자 권한이 필요하므로 `sudo`를 사용한다.

```bash
sudo ./tcp_packet_analyzer eth0
```

## 트래픽 발생 예시

다른 터미널에서 아래 명령어를 실행하여 웹 트래픽을 발생시킨다.

HTTPS 트래픽 발생:

```bash
curl https://whsedu.kr/home/kor/main.do
```

HTTP 트래픽 발생:

```bash
curl http://neverssl.com
```

## 출력 정보

프로그램은 TCP 패킷에서 다음 정보를 출력한다.

- 출발지 MAC 주소
- 목적지 MAC 주소
- 출발지 IP 주소
- 목적지 IP 주소
- 출발지 TCP 포트
- 목적지 TCP 포트
- TCP Payload / HTTP Message

## 참고 사항

HTTPS 트래픽은 암호화되어 있으므로 TCP Payload가 평문 HTTP Message로 보이지 않는다.

반면 HTTP 트래픽은 암호화되지 않기 때문에 TCP Payload 영역에서 `HTTP/1.1 200 OK`, `Content-Type`, `<html>` 등의 내용을 확인할 수 있다.

