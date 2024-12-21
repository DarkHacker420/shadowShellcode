# evasion.py

def sleep():
    s = 500000

    for i in range(s + 1):
        for j in range(2, i // 2 + 1):
            if i % j == 0:
                break

# Example usage
if __name__ == '__main__':
    sleep()
