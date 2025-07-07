TARGET    = fakedns
CXX       = g++
CXXFLAGS  = -std=c++23 -Wall -Wextra -Wpedantic -O2

SRC       = $(wildcard src/*.cpp)
OBJ       = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(TARGET)

re: fclean all

.PHONY: all clean fclean re