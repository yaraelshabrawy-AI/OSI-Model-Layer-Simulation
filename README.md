# OSI-Model-Layer-Simulation
OSI Model Simulator (C++)

Project Overview

This project is a C++ simulation of the OSI (Open Systems Interconnection) Model, demonstrating how data travels through the seven network layers during communication between a sender and a receiver.

The project simulates the process of encapsulation and decapsulation, showing how each layer adds or removes its own information while transmitting data.

 Project Objectives

* Understand the functionality of the seven OSI layers.
* Simulate data transmission between two devices.
* Demonstrate encapsulation and decapsulation.
* Implement basic error detection mechanisms.
* Understand how data is converted into binary bits during transmission.

OSI Model Layers

The project implements all seven layers:

Layer	Name	Main Function
7	Application	Simulates HTTP headers
6	Presentation	XOR encryption and HEX encoding
5	Session	Session ID management
4	Transport	TCP-like headers, ports, sequence numbers, and checksum
3	Network	IP addressing
2	Data Link	MAC addressing and Frame Check Sequence (FCS)
1	Physical	Converts data into binary bits

Main Features

* Full OSI Stack Simulation: Implements all seven layers.
* Encapsulation: Adds layer-specific headers during data transmission.
* Decapsulation: Removes headers at the receiver side.
* Error Detection: Detects corrupted or incomplete data.
* Data Encoding: Converts transmitted data into binary representation.
* Encryption Demonstration: Uses XOR encryption in the Presentation Layer.
* Automated Testing: Includes tests to verify layer functionality and data integrity.
* Verbose Mode: Displays the operations performed at each layer.

Testing

The project includes four main test categories:

1. Individual Layer Testing: Checks whether each layer can correctly encapsulate and decapsulate data.
2. Full Stack Testing: Verifies successful communication between sender and receiver.
3. Error Detection Testing: Checks corrupted bits, truncated signals, and invalid data.
4. Encryption Testing: Ensures that plaintext is not directly visible after Presentation Layer encoding.

Technologies Used

* Programming Language: C++
* Standard: C++17
* Object-Oriented Programming (OOP)
* STL (Standard Template Library)
* Smart Pointers (unique_ptr)

How to Run

Requirements

* A C++ compiler supporting C++17.
* GCC or MinGW.

Compilation

Open the terminal in the project directory and run:

g++ -std=c++17 -Wall -o osi OSI-Model-Layer-Simlation.cpp

Execution

./osi

On Windows:

osi.exe

Project Structure

OSI-Model-Simulator/
│
├── OSI-Model-Layer-Simlation.cpp
└── README.md

What I Learned

Through this project, I practiced:

* Applying Object-Oriented Programming concepts.
* Working with inheritance and polymorphism.
* Understanding the OSI networking architecture.
* Implementing data encapsulation and decapsulation.
* Using exception handling for error detection.
* Writing automated test cases in C++.

Author

Yara Elshabrawy 

Developed as a C++ Networking project to demonstrate the seven layers of the OSI Model and understand the fundamentals of network communication.
