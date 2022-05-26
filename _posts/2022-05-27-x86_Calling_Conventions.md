---
title: x86 Calling Conventions
date: 2022-05-27 13:00:00 +/-TTTT
categories: [Reverse Engineering, Assembly]
tags: [reverse engineering]     # TAG names should always be lowercase
---

# x86 Calling Conventions

In this article, we will talk about;

- What is calling convention and how can we recognize these calling conventions ?
- Why are calling conventions important ?

## What is Calling Convention ?

The term “calling convention” describes;

- how arguments passed to the function and how values are returned from functions,
- whether the caller or the callee will cleans the stack.

There are different conventions based on processor, OS and language. Also, not every compiler implements the “calling conventions” the same way. Therefore, only the standard 4 calling conventions will be discussed in this article.

- __cdecl
- __stdcall
- __fastcall
- __thiscall

Also, developers can sometimes use custom calling conventions. For detailed information on this subject, you can subscribe to [OALabs from Patreon](https://www.patreon.com/oalabs) and view the __usercall tutorial. They have very good videos on this subject.

### __cdecl

__cdecl (which stands for C declaration) is the default calling convention in C and C++. Therefore, you will come across this definition many times while reading assembly in tools such as IDA and Ghidra.

Characteristics of **__cdecl:**

1. Arguments are passed **on the stack in reverse order** (pushed right-to-left),
2. **Caller** cleans the stack.
3. The return value is stored in **EAX**.

Let's say we have a function called "sumNumbers" and it takes 5 integer arguments, then returns the sum of these numbers.

```cpp
#include <iostream>

int sumNumbers(int number1, int number2, int number3, int number4, int number5)
{
    int numSum = number1 + number2 + number3 + number4 + number5;
    return numSum;

}
int main()
{
    int numberSum = 0;
    numberSum = sumNumbers(1, 2, 3, 4, 5);
    printf("Result: %d",numberSum);
}
```

After compiling this code, when we open it in a tool like Ghidra or IDA, it will look like below.

![Untitled](/assets/img/calling_conventions/Untitled.png)

- As seen in the first box, the arguments were passed to the stack in reverse order, then the function called. Which is the first key point to recognize __cdecl. **(1)**
- And in the second box, **0x14 (20) is added to the ESP**. As 5 arguments are sent to the stack and each argument takes up 4 bytes, **caller cleans the stack** 20 byte. **(2)**
- In __cdecl, you will usually see the line **add esp,<area to be cleaned>,** 1 step after the function call.
- And as seen in the last box, the **return value in EAX** is passed to the printf function to be printed. **(3)**
- Also you can see that, the reverse engineering tools usually recognize calling functions. (Blue Underline in screenshot.) But we still won't trust the information there too much. We will examine the reason specifically under the "Why are calling conventions important ? " part.

### __stdcall

__stdcall is the standard calling convention for Win32 API calls. __stdcall characteristics almost identical with __cdecl calling convention.

Characteristics of **__stdcall:**

1. Arguments are passed **on the stack in reverse order** (pushed right-to-left), → Same as __cdecl,
2. Callee cleans the stack.
3. The return value is stored in **EAX**. → Same as __cdecl.

As you can see, the only difference between __cdecl and __stdcall is that, in __cdecl calling convention caller cleans the stack, while in __stdcall calling convention callee cleans the stack.

In this example we will look at the InternetOpenA API, which takes 5 arguments;

```cpp
HINTERNET InternetOpenA(
  [in] LPCSTR lpszAgent,
  [in] DWORD  dwAccessType,
  [in] LPCSTR lpszProxy,
  [in] LPCSTR lpszProxyBypass,
  [in] DWORD  dwFlags
);
```

Let’s compile the code below for analyzing InternetOpenA WIN32 API.

```cpp
#include <iostream>

#pragma comment(lib, "wininet.lib")
#include <WinSock2.h>
#include <wininet.h>

int main()
{
    std::string RESULT{};
    const int size = 4096;
    char buf[size];
    DWORD length;

    HINTERNET internet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
    if (!internet)
        ExitProcess(EXIT_FAILURE);

    HINTERNET response = InternetOpenUrlA(internet, "http://www.google.com", NULL, NULL, NULL, NULL);
    if (!response) {
        InternetCloseHandle(internet);
        ExitProcess(EXIT_FAILURE);
    }
    InternetReadFile(response, buf, size, &length);
    InternetCloseHandle(response);
    InternetCloseHandle(internet);

    std::cout << buf << std::endl;
    return 0;
}
```

After compiling this code, when we open it in a tool like Ghidra or IDA, it will look like below.

![Untitled](/assets/img/calling_conventions/Untitled%201.png)

- As seen in the first box, the 5 parameters requested by the InternetOpenA API were **passed to the stack in reverse order**. **(1)**
- In the second box, after the InternetOpenA **result is returned in EAX,** it is moved to the [ebp+hInternet] address and checked if it is equal to 0 or not. **(3)**
- As a result, the caller did not take any action to clear the stack. Because the **callee (the InternetOpenA function itself) is responsible for stack cleaning**. **(2)**

As we showed on Ghidra in the previous example, we can see the calling convention of this function on IDA as well. (Hover mouse over the function name.)

![Untitled](/assets/img/calling_conventions/Untitled%202.png)

### __fastcall

The main difference of __fastcall is that the initial arguments are passed to the registers instead of pushing to the stack. It’s faster to keep data in registers than in memory, so it’s called **FAST** call.

Characteristics of **__fastcall**:

- First two or three parameters will be passed in the registers EDX, ECX or EAX, and additional parameters are passed on to the stack.
- The return value is stored in **EAX**.
- **Callee** cleans the stack.

*The first two DWORD or smaller arguments that are found in the argument list from left to right are passed in ECX and EDX registers; all other arguments are passed on the stack from right to left.* **(Microsoft)**

Let’s compile the code below and analyze it in IDA.

```cpp
#include <iostream>

int __fastcall TestFunction(int num1, int num2, int num3, int num4, int num5)
{
    int nSum = 0;
    nSum = num1 + num2 + num3 + num4 + num5;
    return nSum;
}

int main()
{
    int nSum = 0;
    nSum = TestFunction(10, 20, 30, 40, 50);
    printf("Result: %d", nSum);
    return 0;
}
```

![Untitled](/assets/img/calling_conventions/Untitled%203.png)

- By looking at the first box, you can see that the **first 2 parameters are passed in the ECX and EDX** and the **other parameters are passed on to the stack**. **(1)**
- In the second box, **return value stored in EAX** and passed to the printf function. **(2)**
- We told that the **callee is responsible for stack cleaning (not registers)**, so in the last box you can see **caller** cleaning 8 bytes. 8/4=2 parameters. Which they are **ECX** and **EDX**.

To see how callee handles stack cleaning, let’s jump into that function;

![Untitled](/assets/img/calling_conventions/Untitled%204.png)

- Since the first 2 arguments cleaned from ECX and EDX by caller, there is only 3 arguments left to be cleaned from stack. You can see in the box, **callee cleans up the stack** by using an operand to the **retn** instruction of **0Ch** (12). So the extra **12-bytes** (12/4 = 3 arguments) to be cleaned up **from stack** during the return operation.
- You can also see that IDA recognizes that this function uses the __fastcall calling convention.

### __thiscall

The Microsoft-specific **__thiscall** calling convention is used on C++ class member functions on the x86 architecture. (passing the **“this”** object) 

Characteristics of **__thiscall**:

- Arguments are passed **on the stack in reverse order** (pushed right-to-left).
- The **“this”** object pointer is passed via **ECX** register**.**
- **Callee** is responsible for stack cleanup.

Let’s compile a simple code to analyze __thiscall.

```cpp
#include <iostream>
using namespace std;

class Numbers {
public:
    int sumNumbers(int num1, int num2);
};

int Numbers::sumNumbers(int num1,int num2) {
    int nSum = 0;
    nSum = num1 + num2;
    return nSum;
}

int main() {
    Numbers myObj; // Create an object of Numbers
    cout << myObj.sumNumbers(200,100); // Call the method with an argument
    return 0;
}
```

![Untitled](/assets/img/calling_conventions/Untitled%205.png)

- Parameters (100,200) are **passed to the stack in reverse order.** Actually, we called as (200,100)
- The **“this”** object pointer stored in **ECX.**

To see where the stack cleaning job is done, let’s jump into the function.

![Untitled](/assets/img/calling_conventions/Untitled%206.png)

- You can see in the box, **callee cleans up the stack** by using an operand to the **retn** instruction of **8**. So the extra **8-bytes** (8/4 = 2 arguments) to be cleaned up **from stack** during the return operation.
- You can also see that IDA recognizes **__thiscall.**

## Why are calling conventions important ?

To understand why calling conventions are important, let's take a step back and look again at our __fastcall example. We analyzed the code we compiled for our __fastcall example using IDA, and everything looked fine. This time, let's examine the same sample file in the Ghidra tool.

![Untitled](/assets/img/calling_conventions/Untitled%207.png)

Let's remember the parameter handling method of __fastcall.

- *First two or three parameters will be passed in the registers EDX, ECX or EAX, and additional parameters are passed on to the stack.*

As you can see in the first box, the first two parameters are passed to ECX and EDX, and the remaining parameters are passed to the stack. But still the Ghidra tool says this function uses the __cdecl calling convention. 

Therefore, instead of relying on such tools, it will be safer to recognize the calling convention when looking ahead in terms of following the parameters.

## Test It Yourself !!!

If you want to repeat the steps in this article, you can use 3 easy methods;

### 1. Use Online Compiler Explorer

*Compiler Explorer is an interactive **online** compiler which shows the **assembly**  output of compiled C++, Rust, Go (and many more) code.*

You can see the assembly output by copying the C++ codes used in this article and pasting them into [Compiler Explorer](https://godbolt.org/).

Don’t forget the choose;

Language: **C++**

Compiler: **x86 msvc v19.latest**

> In this method, you will not see the calling convention. You can interpret it yourself by reading assembly.
{: .prompt-warning }

### 2. Compile It In Your Local Environment

The codes used in this article were compiled using Visual Studio 2022. You can compile the codes yourself using Visual Studio.

> Since the functions used in this article are simple and static, if you do not turn off the ‘Compiler Optimization’ feature, you may not see the function call when examining the assembly. ‘Compiler Optimization’ will calculate and compile the result directly instead of compiling the function because the function is static.
{: .prompt-warning }

To disable ‘Compiler Optimization’ in Visual Studio follow the steps;

- Project - ProjectName Properties - C/C++ - Optimization - Change Optimization to **Disabled**.

### 3. Download the Files Used in This Article

You can download the compiled version of all the codes used in this article from my Github repository.

[Calling Convention Examples](https://github.com/tufan-gungor/Calling-Conventions)

## References

1. [OALabs Youtube](https://www.youtube.com/watch?v=9lzW0I9_cpY) **(Patreon subscription is highly recommended!)**
2. [Microsoft Calling Conventions](https://docs.microsoft.com/en-us/cpp/cpp/calling-conventions?view=msvc-170)
3. [Compiler Explorer](https://godbolt.org/)