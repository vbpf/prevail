#pragma once
/*********************************************************************************
MiniSat -- Copyright (c) 2003-2006, Niklas Een, Niklas Sorensson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************************/
#include <vector>

namespace prevail {

// A heap implementation with support for decrease/increase key.
class Heap {
    std::function<bool(int, int)> lt; // comparison function
    std::vector<int> heap;            // heap of ints
    std::vector<int> indices;         // int -> index in heap

    // Index "traversal" functions
    static int left(const int i) { return i * 2 + 1; }
    static int right(const int i) { return (i + 1) * 2; }
    static int parent(const int i) { return (i - 1) >> 1; }

    void percolateUp(int i) {
        const int x = heap[i];
        while (i != 0 && lt(x, heap[parent(i)])) {
            const int v = heap[i] = heap[parent(i)];
            indices[v] = i;
            i = parent(i);
        }
        heap[i] = x;
        indices[x] = i;
    }

    void percolateDown() {
        int i = 0;
        const int x = heap[i];
        const int size = heap.size();
        while (left(i) < size) {
            int ri = right(i);
            int li = left(i);
            const int child = ri < size && lt(heap[ri], heap[li]) ? ri : li;
            if (!lt(heap[child], x)) {
                break;
            }
            const int v = heap[i] = heap[child];
            indices[v] = i;
            i = child;
        }
        heap[i] = x;
        indices[x] = i;
    }

  public:
    explicit Heap(const std::function<bool(int, int)>& lt) : lt{lt} {}

    [[nodiscard]]
    int size() const {
        return heap.size();
    }

    [[nodiscard]]
    bool empty() const {
        return heap.empty();
    }

    [[nodiscard]]
    bool inHeap(const int n) const {
        return static_cast<size_t>(n) < indices.size() && indices[n] >= 0;
    }

    int operator[](const int index) const {
        assert(static_cast<size_t>(index) < heap.size());
        return heap[index];
    }

    void decrease(const int n) {
        assert(inHeap(n));
        percolateUp(indices[n]);
    }

    void insert(const int n) {
        assert(n >= 0);
        if (static_cast<size_t>(n) >= indices.size()) {
            indices.resize(n + 1, -1);
        }
        assert(!inHeap(n));

        indices[n] = static_cast<int>(heap.size());
        heap.push_back(n);
        percolateUp(indices[n]);
    }

    int removeMin() {
        const int x = heap[0];
        const int v = heap[0] = heap.back();
        indices[v] = 0;
        indices[x] = -1;
        heap.pop_back();
        if (heap.size() > 1) {
            percolateDown();
        }
        return x;
    }
};
} // namespace prevail
