import sys
i, n = int(sys.argv[1]), int(sys.argv[2])
rows = [l.strip() for l in open("hubrefs.txt") if l.strip()]
open("slice_%d.txt" % i, "w").write("\n".join(rows[i::n]))
print("shard %d/%d -> %d" % (i, n, len(rows[i::n])))
