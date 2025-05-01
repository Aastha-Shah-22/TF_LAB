#include <iostream>
#include <vector>
#include <queue>
#include <stack>
using namespace std;

class Graph{
    int n;
    vector<vector<int>>graph;

    public:

    //initialize n and graph of size n
    Graph(int n): n(n), graph(n){}

    void buildGraph();
    void printGraph();
    void bfsIterative();
    void dfsRecursive();
    void dfsRecursiveHelper(int node, vector<int>&visited);
    void dfsIterative();

};

void Graph::buildGraph(){
    cout<<"To stop,  enter -1 for source and destination"<<endl;
    int source;
    int destination;
    while(true){
        cout<<"Enter the source: ";
        cin>>source;
        cout<<"Enter the destination: ";
        cin>>destination;

        if(source == -1 && destination == -1){
            break;
        }
        if(source >= 0 && source < n && destination >= 0 && destination < n){
            graph[source].push_back(destination);
            graph[destination].push_back(source);
        }
        else{
            cout<<"Enter values of valid range"<<endl;
        }
    }
}

void Graph::printGraph(){
    for(int i = 0; i < this->n; i++){
        cout<<i<<":";
        for(int num: graph[i]){
            cout<<num<<" ";
        }
        cout<<endl;
    }
}

void Graph::bfsIterative(){
    cout<<"BFS traversal is: ";
    vector<int>visited(n, 0);
    queue<int>q;
    q.push(0);
    visited[0] = 1;
    cout<<0<<" ";
    while(!q.empty()){
        int s = q.size();

        for(int i = 0; i < s; i++){
            int ele = q.front();
            q.pop();

            for(int num : graph[ele]){
                if(visited[num] == 0){
                    visited[num] = 1;
                    q.push(num);
                    cout<<num<<" ";
                }
            }
        }
        
    }
}

void Graph::dfsRecursiveHelper(int node, vector<int>&visited){
    visited[node] = 1;
    cout<<node<<" ";

    for(int num: graph[node]){
        if(visited[num] == 0){
            dfsRecursiveHelper(num, visited);
        }
    }
}

void Graph::dfsRecursive(){
    vector<int>visited(n, 0);
    cout<<"DFS Recursive traversal is: ";
    dfsRecursiveHelper(0, visited);
}

void Graph::dfsIterative(){
    cout<<"DFS Iterative is: ";
    stack<int>st;
    vector<int>visited(n, 0);
    st.push(0);
    visited[0] = 1;

    while(!st.empty()){
        int ele = st.top();
        st.pop();
        cout<<ele<<" ";

        for(int num: graph[ele]){
            if(visited[num] == 0){
                visited[num] = 1;
                st.push(num);
            }
        }
    }
    
}

int main(){
    Graph g(5);
    g.buildGraph();
    g.printGraph();
    g.bfsIterative();
    cout<<endl;
    g.dfsRecursive();
    cout<<endl;
    g.dfsIterative();
}