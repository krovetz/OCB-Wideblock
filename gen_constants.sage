# w will iterate over these blocklengths. Edit list as you wish.
for w in [32, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1600]:

   domsize = [0]    # domsize[i] will contain domain size of shift i

   # Find domain size for each possible shift c in 1..w-1
   for c in range(1, w):

      # Build A matrix as specified in Section 4.1 of [OCB]
      I_rows = [[j == i for j in range(w)] for i in range(w)]
      J_rows = [[j == i or j == i + c for j in range(w)]
                                      for i in range(w)]
      IJ = matrix(GF(2), I_rows + J_rows)
      A = [IJ[i:i + w, 0:w] for i in range(w)]
      
      # Find number of qualifying sub-matrices (ie, domain size)
      i = 0         # increase i until not full-rank
      dom = w       # Set dom=i ends loop & sets dom to domain size
      while i < dom:
         if A[i].rank() < w: dom=i
         j = 0
         while j < i and i < dom:
            if (A[i] + A[j]).rank() < w: dom=i
            j = j + 1
         i = i + 1
      domsize.append(dom)   # set domsize[c] = dom

   # Generate shifts that are secure, in preference order
   domain_bits = floor(log(max(domsize), 2))
   candidates = (k for i in range(8)
                   for j in range(floor(log(w, 2)),2,-1)
                   for k in range(i,w,2**j)
                   if domsize[k] >= 2**domain_bits)
   
   # Print the first one found, or -1 if none
   print("block bits: %d, mask bits: %d, shift bits: %d" %
            (w, domain_bits, next(candidates,-1)))
