// Ethereum contract
contract Dog {
    event Bark(string message);
    event TailWag(string message);

    function bark() public {
        emit Bark("Woof! Woof!");
    }

    function wagTail() public {
        emit TailWag("The dog is happy and wagging its tail!");
    }
}