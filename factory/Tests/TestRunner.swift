import Foundation

struct TestFailure: Error, CustomStringConvertible {
    let message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}

struct TestCase {
    let name: String
    let run: () async throws -> Void

    init(_ name: String, _ run: @escaping () async throws -> Void) {
        self.name = name
        self.run = run
    }
}

func expectEqual<T: Equatable>(_ actual: T, _ expected: T, file: StaticString = #file, line: UInt = #line) throws {
    guard actual == expected else {
        throw TestFailure("\(file):\(line): expected \(expected), got \(actual)")
    }
}

func expectTrue(_ condition: Bool, _ message: String = "expected true", file: StaticString = #file, line: UInt = #line) throws {
    guard condition else {
        throw TestFailure("\(file):\(line): \(message)")
    }
}

func expectFalse(_ condition: Bool, _ message: String = "expected false", file: StaticString = #file, line: UInt = #line) throws {
    guard !condition else {
        throw TestFailure("\(file):\(line): \(message)")
    }
}

func expectContains(_ haystack: String, _ needle: String, file: StaticString = #file, line: UInt = #line) throws {
    guard haystack.contains(needle) else {
        throw TestFailure("\(file):\(line): expected '\(haystack)' to contain '\(needle)'")
    }
}

func expectNotContains(_ haystack: String, _ needle: String, file: StaticString = #file, line: UInt = #line) throws {
    guard !haystack.contains(needle) else {
        throw TestFailure("\(file):\(line): expected '\(haystack)' NOT to contain '\(needle)'")
    }
}

@discardableResult
func expectThrows(_ body: () throws -> Void, file: StaticString = #file, line: UInt = #line) throws -> Error {
    do {
        try body()
    } catch {
        return error
    }
    throw TestFailure("\(file):\(line): expected error to be thrown")
}

@discardableResult
func expectThrowsAsync(_ body: () async throws -> Void, file: StaticString = #file, line: UInt = #line) async throws -> Error {
    do {
        try await body()
    } catch {
        return error
    }
    throw TestFailure("\(file):\(line): expected async error to be thrown")
}

@main
struct FactoryTestRunner {
    static func main() async {
        let suite = SealedTests.all + RollbackAndProviderTests.all
        var passed = 0
        var failed = 0

        for test in suite {
            do {
                try await test.run()
                passed += 1
                FileHandle.standardError.write(Data("PASS \(test.name)\n".utf8))
            } catch {
                failed += 1
                FileHandle.standardError.write(Data("FAIL \(test.name): \(error)\n".utf8))
            }
        }

        let summary = "factory-tests: \(passed)/\(suite.count) passed, \(failed) failed\n"
        FileHandle.standardError.write(Data(summary.utf8))
        exit(failed == 0 ? 0 : 1)
    }
}
