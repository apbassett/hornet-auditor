import hornet

for i in range(11):
  if i == 0:
    continue
  fp = f'./test_case_{i}/'
  print(f'****************\nTEST CASE {i}\n****************')
  hornet.main(fp, fp)
  print(f'****************')
