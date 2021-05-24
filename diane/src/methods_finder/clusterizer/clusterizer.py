import sys
import numpy
import matplotlib.pyplot as plt
import pickle

from sklearn.cluster import KMeans

# Apply clustering
def cluster_data(data):
    features = []

    # Compute features
    for func in data:
        func_data = sorted(data[func])

        mean = numpy.mean(func_data)
        std = numpy.std(func_data)
        mode = max(set(func_data), key=func_data.count)

        features.append([mean, mode, std])

    features = numpy.array(features)

    # KMeans - 2 clusters
    kmeans = KMeans(n_clusters=2)
    res = kmeans.fit(features)

    # Plot points
    #
    # plt.scatter(features[:,0], features[:,1], c=kmeans.labels_, cmap='rainbow')
    # plt.show()

    return res

# Cluster data and select functions
def select_funcs(data):
    res = cluster_data(data)

    # Check which is the cluster closer to 0,0
    point_zero = numpy.array((0, 0, 0))
    d1 = numpy.linalg.norm(res.cluster_centers_[0] - point_zero)
    d2 = numpy.linalg.norm(res.cluster_centers_[1] - point_zero)
    cluster_idx = int(d1 > d2)

    sel_funcs = set()

    # Select functions in the right cluster
    for i, cluster in enumerate(res.labels_):
        if cluster == cluster_idx:
            sel_funcs.add(data.keys()[i])

    return sel_funcs


def main():
    print 'Loading data'
    data = pickle.load(open(sys.argv[1], 'rb'))

    funcs = select_funcs(data)
    from IPython import embed
    embed()


if __name__ == '__main__':
    main()
