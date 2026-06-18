#include <iostream>
#include <vector>
#include <queue>
#include <unordered_set>
using namespace std;

const int N = 3;

struct puzzleState{
    vector<vector<int>>puzzle;
    int zeroRow;
    int zeroCol;
    int g;
    int h;

    puzzleState(): puzzle(N, vector<int>(N)){}
};

void printPuzzle(const puzzleState &state){
    for(int i = 0; i < N;i ++){
        for(int j = 0; j < N; j++){
            cout<<state.puzzle[i][j]<<" ";
        }
        cout<<endl;
    }

    cout<<"---------\n";
}

bool isEqual(const puzzleState &state1, const puzzleState &state2){
    for(int i = 0; i < N; i++){
        for(int j = 0; j < N; j++){
            if(state1.puzzle[i][j] != state2.puzzle[i][j]){
                return false;
            }
        }
    }

    return true;
}

// int calculateManhattanDistance(const puzzleState &state, const puzzleState &goalState) {
//     int distance = 0;
//     for (int i = 0; i < N; ++i) {
//         for (int j = 0; j < N; ++j) {
//             int value = state.puzzle[i][j];
//             if (value != 0) {
//                 for (int x = 0; x < N; ++x) {
//                     for (int y = 0; y < N; ++y) {
//                         if (goalState.puzzle[x][y] == value) {
//                             distance += abs(i - x) + abs(j - y);
//                         }
//                     }
//                 }
//             }
//         }
//     }
//     return distance;
// }

int calculateManhattanDistance(const puzzleState &initialState, const puzzleState &finalState){
    int distance = 0;
    for(int i = 0; i < N; i++){
        for(int j = 0; j < N; j++){
            if(initialState.puzzle[i][j] && initialState.puzzle[i][j] != finalState.puzzle[i][j]){
                distance += 1;
            }
        }
    }

    return distance;
}

bool isValid(int row, int col){
    return (row >= 0 && row < N && col >= 0 && col < N);
}

vector<puzzleState> generateNextStates(const puzzleState &currentState, const puzzleState &finalState){
    vector<puzzleState>nextStates;

    vector<vector<int>>dir = {
        {0,1}, {0,-1}, {1,0}, {-1,0}
    };

    for(auto d : dir){
        int nextZeroRow = currentState.zeroRow + d[0];
        int nextZeroCol = currentState.zeroCol + d[1];

        if(isValid(nextZeroRow, nextZeroCol)){
            puzzleState nextState = currentState;
            swap(nextState.puzzle[currentState.zeroRow][currentState.zeroCol], nextState.puzzle[nextZeroRow][nextZeroCol]);
            nextState.zeroCol = nextZeroCol;
            nextState.zeroRow = nextZeroRow;
            nextState.g += 1;
            nextState.h = calculateManhattanDistance(nextState, finalState);
            nextStates.push_back(nextState);
        }
    }

    return nextStates;
}

struct CompareState {
    bool operator()(const puzzleState &a, const puzzleState &b) const {
        return (a.g + a.h) > (b.g + b.h); // min-heap: lower f = higher priority
    }
};


void aStarSearch(const puzzleState &initialState, const puzzleState &finalState){
    priority_queue<puzzleState, vector<puzzleState>, CompareState> pq;
    unordered_set<int> visited;
    pq.push(initialState);

    while (!pq.empty()){
        puzzleState current = pq.top();
        pq.pop();

        cout<<"Current State:\n";
        printPuzzle(current);
        cout<<"Number of moves: "<<current.g<<endl;
        cout<<"Heuristic cost: "<<current.h<<endl;
        cout<<"---------\n";

        if(isEqual(current, finalState)){
            cout<<"Goal State Reached!\n";
            cout << "Number of moves: " << current.g << endl;
            cout << "Heuristic cost: " << current.h << endl;
            break;
        }

        vector<puzzleState>nextStates = generateNextStates(current, finalState);
        for(const puzzleState &nextState : nextStates){
            int hash = 0;
            for(int i = 0; i < N; i++){
                for(int j = 0; j < N; j++){
                    hash = hash*10 + nextState.puzzle[i][j];
                }
            }

            if(visited.find(hash) == visited.end()){
                pq.push(nextState);
                visited.insert(hash);
            }
        }

    }

}

puzzleState getPuzzleState(){
    puzzleState state;
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            cout << "Enter value at position (" << i << ", " << j << "): ";
            cin >> state.puzzle[i][j];

            if (state.puzzle[i][j] == 0)
            {
                state.zeroRow = i;
                state.zeroCol = j;
            }
        }
    }

    state.g = 0;

    return state;
}

int main()
{
    cout<<"Enter initial state \n";
    puzzleState initialState = getPuzzleState();
    cout<<"Enter final state \n";
    puzzleState finalState = getPuzzleState();
    initialState.h = calculateManhattanDistance(initialState, finalState);

    cout << "Initial State:\n";
    printPuzzle(initialState);

    aStarSearch(initialState, finalState);

    return 0;
}

