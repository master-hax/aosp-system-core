#include <testprop.h>
#include <iostream>
using namespace std;

int main() {
    auto d = my::test::name::space::TEST_DOUBLE.Get();
    if (d)
        cout << *d << endl;
    else
        cout << "test_double empty" << endl;
}
